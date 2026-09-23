//go:build linux

package faketcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var (
	errTimeout   = errors.New("timeout")
	expire       = time.Minute
)

func (conn *FakeTCPPacketConn) logDebug(args ...any) {
	if conn.debug && conn.logger != nil {
		conn.logger.DebugContext(context.Background(), append([]any{"[faketcp] "}, args...)...)
	}
}

func (conn *FakeTCPPacketConn) logWarn(args ...any) {
	if conn.logger != nil {
		conn.logger.WarnContext(context.Background(), append([]any{"[faketcp] "}, args...)...)
	}
}

var (
	packetPool = sync.Pool{
		New: func() any {
			b := make([]byte, 2048)
			return &b
		},
	}
	nftGlobalConn  *nftables.Conn
	nftGlobalTable *nftables.Table
	nftGlobalChain *nftables.Chain
	nftGlobalOnce  sync.Once

	nftRuleMu    sync.Mutex
	nftRuleMap   = make(map[string]*nftRuleEntry)
	nftCleanOnce sync.Once
)

type nftRuleEntry struct {
	refCount int
	rule4    *nftables.Rule
	rule6    *nftables.Rule
}

func initNftables() {
	nftGlobalConn = &nftables.Conn{}

	// attempt to delete existing table to clean up residues
	nftGlobalConn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "sing-box-faketcp"})
	_ = nftGlobalConn.Flush()

	nftGlobalTable = nftGlobalConn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "sing-box-faketcp",
	})
	nftGlobalChain = nftGlobalConn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    nftGlobalTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityRef(-1),
	})
	_ = nftGlobalConn.Flush()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		Cleanup()
	}()
}

// Cleanup deletes the entire sing-box-faketcp nftables table.
// It should be called when the program exits.
func Cleanup() {
	nftCleanOnce.Do(func() {
		if nftGlobalConn != nil && nftGlobalTable != nil {
			nftGlobalConn.DelTable(nftGlobalTable)
			_ = nftGlobalConn.Flush()
		}
	})
}

// nftRuleKey generates a unique key for the rule registry based on IPs and ports.
func nftRuleKey(srcIP, dstIP net.IP, srcPort, dstPort uint16) string {
	return fmt.Sprintf("%s-%s-%d-%d", srcIP.String(), dstIP.String(), srcPort, dstPort)
}

func acquireNftRules(key string, srcIP, dstIP net.IP, srcPort, dstPort uint16) (rule4, rule6 *nftables.Rule) {
	nftRuleMu.Lock()
	defer nftRuleMu.Unlock()

	entry, exists := nftRuleMap[key]
	if exists {
		entry.refCount++
		return entry.rule4, entry.rule6
	}

	entry = &nftRuleEntry{refCount: 1}

	nftGlobalOnce.Do(initNftables)

	isIPv4 := func(ip net.IP) bool { return ip != nil && ip.To4() != nil }
	isIPv6 := func(ip net.IP) bool { return ip != nil && ip.To4() == nil && ip.To16() != nil }

	if isIPv4(srcIP) || isIPv4(dstIP) || (srcIP == nil && dstIP == nil) {
		entry.rule4 = nftGlobalConn.AddRule(&nftables.Rule{
			Table: nftGlobalTable,
			Chain: nftGlobalChain,
			Exprs: buildDropRuleIPv4(srcIP, dstIP, srcPort, dstPort),
		})
	}
	if isIPv6(srcIP) || isIPv6(dstIP) || (srcIP == nil && dstIP == nil) {
		entry.rule6 = nftGlobalConn.AddRule(&nftables.Rule{
			Table: nftGlobalTable,
			Chain: nftGlobalChain,
			Exprs: buildDropRuleIPv6(srcIP, dstIP, srcPort, dstPort),
		})
	}
	_ = nftGlobalConn.Flush()

	// refresh handles for the newly added rules
	rules, err := nftGlobalConn.GetRules(nftGlobalTable, nftGlobalChain)
	if err == nil {
		for _, r := range rules {
			if entry.rule4 != nil && entry.rule4.Handle == 0 {
				if len(r.Exprs) == len(entry.rule4.Exprs) && isIPv4Rule(r) {
					entry.rule4.Handle = r.Handle
				}
			}
			if entry.rule6 != nil && entry.rule6.Handle == 0 {
				if len(r.Exprs) == len(entry.rule6.Exprs) && !isIPv4Rule(r) {
					entry.rule6.Handle = r.Handle
				}
			}
		}
	}

	nftRuleMap[key] = entry
	return entry.rule4, entry.rule6
}

func releaseNftRules(key string) {
	nftRuleMu.Lock()
	defer nftRuleMu.Unlock()

	entry, exists := nftRuleMap[key]
	if !exists {
		return
	}

	entry.refCount--
	// Keep the rule alive until Cleanup() is called to avoid rule gap and races.
}

// isIPv4Rule checks if the rule matches NFPROTO_IPV4 (first Cmp expression)
func isIPv4Rule(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if cmp, ok := e.(*expr.Cmp); ok {
			if len(cmp.Data) == 1 {
				return cmp.Data[0] == unix.NFPROTO_IPV4
			}
		}
	}
	return false
}

func toUDPAddr(addr net.Addr) net.Addr {
	if ta, ok := addr.(*net.TCPAddr); ok {
		return &net.UDPAddr{IP: ta.IP, Port: ta.Port, Zone: ta.Zone}
	}
	return addr
}

func toTCPAddr(addr net.Addr) net.Addr {
	if ua, ok := addr.(*net.UDPAddr); ok {
		return &net.TCPAddr{IP: ua.IP, Port: ua.Port, Zone: ua.Zone}
	}
	return addr
}

func setDF(c *net.IPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.IPAddr)

	var innerErr error
	if addr.IP.To4() != nil {
		raw.Control(func(fd uintptr) {
			innerErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
		})
	} else {
		raw.Control(func(fd uintptr) {
			innerErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IPV6_PMTUDISC_DO)
		})
	}
	return innerErr
}

// a message from NIC
type message struct {
	bts     []byte
	addr    net.Addr
	poolBuf *[]byte
}

// a tcp flow information of a connection pair
// TCPTracker tracks sequence and acknowledgment numbers for a TCP flow.
type TCPTracker struct {
	Seq     atomic.Uint32
	SeqInit atomic.Bool
	Ack     atomic.Uint32
}

// Update updates flow state (seq/ack) from an incoming TCP packet
func (t *TCPTracker) Update(seq uint32, ack uint32, payloadLen int, isACK, isSYN, isFIN bool) {
	if isACK && !t.SeqInit.Load() {
		t.Seq.Store(ack)
		t.SeqInit.Store(true)
	}
	// Update ACK: advance ack for in-order packets
	nextSeq := seq + uint32(payloadLen)
	if isSYN {
		nextSeq++
	}
	if isFIN {
		nextSeq++
	}
	if nextSeq != seq {
		// Always advance ACK to highest seen to prevent conntrack invalidation on packet loss
		currentAck := t.Ack.Load()
		if currentAck == 0 || int32(nextSeq-currentAck) > 0 {
			t.Ack.Store(nextSeq)
		}
	}
}

// AdvanceSeq advances the flow's sequence number by n bytes.
func (t *TCPTracker) AdvanceSeq(n int) {
	t.Seq.Add(uint32(n))
}

// a tcp flow information of a connection pair
type tcpFlow struct {
	conn           atomic.Pointer[net.TCPConn] // the related system TCP connection of this flow
	handle         atomic.Pointer[net.IPConn]  // the handle to send packets
	tracker        TCPTracker                  // TCP sequence and ACK tracker
	ts             atomic.Int64                // last packet incoming time
	pseudoSum      atomic.Uint32               // Cached pseudo-header checksum
	pseudoSumReady atomic.Bool                 // Whether pseudoSum has been computed
	srcIP          atomic.Pointer[net.IP]      // Cached source IP for checksum
	
	// statistics
	txBytes      atomic.Uint64
	rxBytes      atomic.Uint64
	txPackets    atomic.Uint64
	rxPackets    atomic.Uint64
	dropOrphan   atomic.Uint64
	dropBuffer   atomic.Uint64
	dropNoHandle atomic.Uint64

	remoteAddr   string
}

type flowKey struct {
	IP   [16]byte
	Port int
}

func addrToKey(addr *net.TCPAddr) flowKey {
	var k flowKey
	k.Port = addr.Port
	if ip16 := addr.IP.To16(); ip16 != nil {
		copy(k.IP[:], ip16)
	}
	return k
}

func keyToAddr(key flowKey) string {
	ip := net.IP(key.IP[:])
	return net.JoinHostPort(ip.String(), fmt.Sprint(key.Port))
}

// FakeTCPPacketConn defines a TCP-packet oriented connection
type FakeTCPPacketConn struct {
	die     chan struct{}
	dieOnce sync.Once

	// the main golang sockets
	tcpconn  *net.TCPConn     // from net.Dial
	listener *net.TCPListener // from net.Listen

	// handles
	handles []*net.IPConn

	logger logger.ContextLogger
	debug  bool

	// packets captured from all related NICs will be delivered to this channel
	chMessage chan message

	// all TCP flows
	flowTable sync.Map

	// nftables
	nftRule4 *nftables.Rule
	nftRule6 *nftables.Rule
	nftKey   string

	// deadlines
	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

func (conn *FakeTCPPacketConn) getFlow(key flowKey) *tcpFlow {
	if v, ok := conn.flowTable.Load(key); ok {
		return v.(*tcpFlow)
	}
	e := new(tcpFlow)
	e.remoteAddr = keyToAddr(key)
	e.ts.Store(time.Now().UnixNano())
	if actual, loaded := conn.flowTable.LoadOrStore(key, e); loaded {
		return actual.(*tcpFlow)
	}
	return e
}

func (conn *FakeTCPPacketConn) removeFlow(key flowKey, e *tcpFlow, reason string) {
	conn.flowTable.Delete(key)
	if conn.debug && conn.logger != nil {
		txB := e.txBytes.Load()
		rxB := e.rxBytes.Load()
		txP := e.txPackets.Load()
		rxP := e.rxPackets.Load()
		dO := e.dropOrphan.Load()
		dB := e.dropBuffer.Load()
		dNH := e.dropNoHandle.Load()
		
		conn.logger.DebugContext(context.Background(),
			"[faketcp] flow closed (", reason, ") [", e.remoteAddr, "] ",
			"Rx: ", rxB, " bytes (", rxP, " pkts), ",
			"Tx: ", txB, " bytes (", txP, " pkts). ",
			"Drops: ", dO+dB+dNH, " (Orphan:", dO, ", BufferFull:", dB, ", NoHandle:", dNH, ")",
		)
	}
}

// clean expired flows
func (conn *FakeTCPPacketConn) cleaner() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-conn.die:
			return
		case <-ticker.C:
			conn.flowTable.Range(func(key, value any) bool {
				v := value.(*tcpFlow)
				if time.Since(time.Unix(0, v.ts.Load())) > expire {
					c := v.conn.Load()
					if c != nil {
						setTTL(c, 64)
						c.Close()
					}
					conn.removeFlow(key.(flowKey), v, "timeout")
				}
				return true
			})
		}
	}
}

// captureFlow capture every inbound packets
func (conn *FakeTCPPacketConn) captureFlow(handle *net.IPConn, port int) {
	conn.logDebug("[faketcp] captureFlow: started on ", handle.LocalAddr().String(), " port=", port)
	var dropCount uint64
	var lastDropLog time.Time
	for {
		// Zero-copy: allocate poolBuf directly instead of large local array
		poolBuf := packetPool.Get().(*[]byte)
		buf := *poolBuf
		n, addr, err := handle.ReadFromIP(buf)
		if err != nil {
			packetPool.Put(poolBuf)
			select {
			case <-conn.die:
				return
			default:
				conn.logWarn("[faketcp] captureFlow: ReadFromIP error: ", err, " on ", handle.LocalAddr().String())
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		// Fast TCP Parsing
		if n < 20 {
			packetPool.Put(poolBuf)
			continue
		}
		dataOffset := (buf[12] >> 4) * 4
		if int(dataOffset) < 20 || int(dataOffset) > n {
			packetPool.Put(poolBuf)
			continue
		}

		dstPort := int(binary.BigEndian.Uint16(buf[2:4]))
		// port filtering
		if dstPort != port {
			packetPool.Put(poolBuf)
			continue
		}

		srcPort := int(binary.BigEndian.Uint16(buf[0:2]))
		seq := binary.BigEndian.Uint32(buf[4:8])
		ack := binary.BigEndian.Uint32(buf[8:12])
		flags := buf[13]
		isACK := (flags & 0x10) != 0
		isSYN := (flags & 0x02) != 0
		isFIN := (flags & 0x01) != 0

		payloadLen := n - int(dataOffset)

		// address building (stack allocated)
		src := net.TCPAddr{
			IP:   addr.IP,
			Port: srcPort,
		}

		// flow maintaince
		key := addrToKey(&src)
		e := conn.getFlow(key)
		e.rxPackets.Add(1)
		e.rxBytes.Add(uint64(n))

		if e.handle.Load() == nil {
			e.handle.Store(handle)
		}

		e.tracker.Update(seq, ack, payloadLen, isACK, isSYN, isFIN)

		// push data if it has payload
		if payloadLen > 0 {
			e.ts.Store(time.Now().UnixNano())

			// Wait briefly for AcceptTCP to complete if conn not yet set
			// (race: raw socket receives data before kernel TCP handshake finishes)
			if e.conn.Load() == nil {
				waited := false
				for range 50 {
					time.Sleep(10 * time.Millisecond)
					if e.conn.Load() != nil {
						waited = true
						break
					}
				}
				if !waited {
					e.dropOrphan.Add(1)
					packetPool.Put(poolBuf)
					continue
				}
			}

			// Zero-copy slice of the payload
			pbuf := buf[dataOffset:n]

			// notify FakeTCPPacketConn.ReadFrom
			select {
			// Pass address by pointer (escapes here, but avoids alloc for dropped packets)
			case conn.chMessage <- message{bts: pbuf, addr: &net.TCPAddr{IP: addr.IP, Port: srcPort}, poolBuf: poolBuf}:
			case <-conn.die:
				packetPool.Put(poolBuf)
				return
			default:
				// drop packet if buffer is full to avoid blocking captureFlow
				packetPool.Put(poolBuf)
				e.dropBuffer.Add(1)
				dropCount++
				now := time.Now()
				if now.Sub(lastDropLog) > time.Second {
					lastDropLog = now
					conn.logWarn("[faketcp] chMessage is full, recently dropped packets: ", dropCount)
					dropCount = 0
				}
			}
		} else {
			// No payload, return the buffer to the pool immediately
			packetPool.Put(poolBuf)
		}
	}
}

// ReadFrom implements the PacketConn ReadFrom method.
func (conn *FakeTCPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := conn.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-deadline:
		return 0, nil, errTimeout
	case <-conn.die:
		return 0, nil, io.EOF
	case packet := <-conn.chMessage:
		n = copy(p, packet.bts)
		if n < len(packet.bts) {
			log.Printf("[faketcp] GRO warning: packet truncated from %d to %d. Please disable GRO on your network interface (e.g., ethtool -K eth0 gro off)", len(packet.bts), n)
		}
		if packet.poolBuf != nil {
			packetPool.Put(packet.poolBuf)
		}
		return n, toUDPAddr(packet.addr), nil
	}
}

// WriteTo implements the PacketConn WriteTo method.
func (conn *FakeTCPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if d, ok := conn.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		if time.Now().After(d) {
			return 0, errTimeout
		}
	}

	select {
	case <-conn.die:
		return 0, io.EOF
	default:
	}

	var raddr *net.TCPAddr
	taddr := toTCPAddr(addr)
	if ta, ok := taddr.(*net.TCPAddr); ok {
		raddr = ta
	} else {
		var errResolve error
		raddr, errResolve = net.ResolveTCPAddr("tcp", taddr.String())
		if errResolve != nil {
			return 0, errResolve
		}
	}

	var lport int
	if conn.tcpconn != nil {
		lport = conn.tcpconn.LocalAddr().(*net.TCPAddr).Port
	} else {
		lport = conn.listener.Addr().(*net.TCPAddr).Port
	}

	key := addrToKey(raddr)
	e := conn.getFlow(key)

	handle := e.handle.Load()

	if handle == nil {
		e.dropNoHandle.Add(1)
		n = len(p)
		return n, nil
	}

	e.txPackets.Add(1)
	e.txBytes.Add(uint64(len(p)))

	// Manual fast-path TCP serialization (zero allocation, no gopacket)
	tcpLenInt := 20 + len(p)
	if tcpLenInt > 65535 {
		return 0, fmt.Errorf("packet too large: %d", tcpLenInt)
	}
	tcpLen := uint16(tcpLenInt)

	// Use a pooled buffer for the TCP segment (Header + Payload)
	bufPtr := packetPool.Get().(*[]byte)
	if cap(*bufPtr) < tcpLenInt {
		b := make([]byte, tcpLenInt)
		bufPtr = &b
	}
	buf := (*bufPtr)[:tcpLenInt]

	// 0:2 SrcPort, 2:4 DstPort
	binary.BigEndian.PutUint16(buf[0:2], uint16(lport))
	binary.BigEndian.PutUint16(buf[2:4], uint16(raddr.Port))

	// 4:8 Seq, 8:12 Ack
	ack := e.tracker.Ack.Load()
	if !e.tracker.SeqInit.Load() {
		// Sequence not initialized yet, drop packet silently to let QUIC handle retransmission naturally
		packetPool.Put(bufPtr)
		return len(p), nil
	}
	payloadLen := uint32(len(p))
	newSeq := e.tracker.Seq.Add(payloadLen)
	seq := newSeq - payloadLen

	binary.BigEndian.PutUint32(buf[4:8], seq)
	binary.BigEndian.PutUint32(buf[8:12], ack)

	// 12 DataOffset (5 << 4) + Reserved
	buf[12] = 0x50
	// 13 Flags (PSH | ACK)
	buf[13] = 0x18
	// 14:16 Window (65535)
	binary.BigEndian.PutUint16(buf[14:16], 65535)
	// 16:18 Checksum (initially 0)
	buf[16] = 0
	buf[17] = 0
	// 18:20 Urgent Pointer (0)
	buf[18] = 0
	buf[19] = 0

	// Copy payload
	copy(buf[20:], p)

	// Resolve SrcIP for Checksum (cached per flow)
	var srcIP net.IP
	if cached := e.srcIP.Load(); cached != nil {
		srcIP = *cached
	} else {
		srcIP = handle.LocalAddr().(*net.IPAddr).IP
		if len(srcIP) == 0 || srcIP.IsUnspecified() {
			// For unbound raw sockets, resolve source IP from the flow's
			// accepted TCP connection (set by AcceptTCP in the server goroutine)
			if flowConn := e.conn.Load(); flowConn != nil {
				srcIP = flowConn.LocalAddr().(*net.TCPAddr).IP
			} else if conn.tcpconn != nil {
				srcIP = conn.tcpconn.LocalAddr().(*net.TCPAddr).IP
			} else if conn.listener != nil {
				srcIP = conn.listener.Addr().(*net.TCPAddr).IP
			}
		}
		if len(srcIP) == 0 {
			srcIP = net.IPv4(127, 0, 0, 1) // Fallback for edge cases
		}
		e.srcIP.Store(&srcIP)
	}

	// Calculate Checksum (pseudo-header checksum cached per flow)
	var pSum uint32
	if !e.pseudoSumReady.Load() {
		isIPv6 := len(srcIP) == 16 && srcIP.To4() == nil
		pSum = pseudoHeaderChecksum(srcIP, raddr.IP, isIPv6)
		e.pseudoSum.Store(pSum)
		e.pseudoSumReady.Store(true)
	} else {
		pSum = e.pseudoSum.Load()
	}
	csum := fastTCPChecksum(pSum, tcpLen, buf[0:20], p)
	binary.BigEndian.PutUint16(buf[16:18], csum)

	// Write to raw socket
	if conn.tcpconn != nil {
		_, err = handle.Write(buf)
	} else {
		var ipAddr net.IPAddr
		ipAddr.IP = raddr.IP
		_, err = handle.WriteToIP(buf, &ipAddr)
	}

	packetPool.Put(bufPtr)
	n = len(p)
	return
}

// Close closes the connection.
func (conn *FakeTCPPacketConn) Close() error {
	var err error
	conn.dieOnce.Do(func() {
		// signal closing
		close(conn.die)

		// drain chMessage
	drainLoop:
		for {
			select {
			case msg := <-conn.chMessage:
				if msg.poolBuf != nil {
					packetPool.Put(msg.poolBuf)
				}
			default:
				break drainLoop
			}
		}

		// close all established tcp connections
		if conn.tcpconn != nil { // client
			setTTL(conn.tcpconn, 64)
			err = conn.tcpconn.Close()
		} else if conn.listener != nil {
			err = conn.listener.Close() // server
			conn.flowTable.Range(func(key, value any) bool {
				v := value.(*tcpFlow)
				c := v.conn.Load()
				if c != nil {
					setTTL(c, 64)
					c.Close()
				}
				conn.removeFlow(key.(flowKey), v, "server closed")
				return true
			})
		}

		// close handles
		for k := range conn.handles {
			conn.handles[k].Close()
		}

		if conn.nftKey != "" {
			releaseNftRules(conn.nftKey)
		}
	})
	return err
}

// LocalAddr returns the local network address.
func (conn *FakeTCPPacketConn) LocalAddr() net.Addr {
	if conn.tcpconn != nil {
		return toUDPAddr(conn.tcpconn.LocalAddr())
	} else if conn.listener != nil {
		return toUDPAddr(conn.listener.Addr())
	}
	return nil
}

// SetDeadline implements the Conn SetDeadline method.
func (conn *FakeTCPPacketConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (conn *FakeTCPPacketConn) SetReadDeadline(t time.Time) error {
	conn.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (conn *FakeTCPPacketConn) SetWriteDeadline(t time.Time) error {
	conn.writeDeadline.Store(t)
	return nil
}

// SetDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
func (conn *FakeTCPPacketConn) SetDSCP(dscp int) error {
	for k := range conn.handles {
		if err := setDSCP(conn.handles[k], dscp); err != nil {
			return err
		}
	}
	return nil
}

// SetReadBuffer sets the size of the operating system's receive buffer associated with the connection.
func (conn *FakeTCPPacketConn) SetReadBuffer(bytes int) error {
	var err error
	for k := range conn.handles {
		if err := conn.handles[k].SetReadBuffer(bytes); err != nil {
			return err
		}
	}
	return err
}

// SetWriteBuffer sets the size of the operating system's transmit buffer associated with the connection.
func (conn *FakeTCPPacketConn) SetWriteBuffer(bytes int) error {
	var err error
	for k := range conn.handles {
		if err := conn.handles[k].SetWriteBuffer(bytes); err != nil {
			return err
		}
	}
	return err
}

// DialPacket connects to the remote TCP port,
// and returns a single packet-oriented connection
func DialPacket(remoteAddr string, l logger.ContextLogger, debug bool) (*FakeTCPPacketConn, error) {
	raddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		return nil, err
	}

	// AF_INET
	handle, err := net.DialIP("ip:tcp", nil, &net.IPAddr{IP: raddr.IP})
	if err != nil {
		return nil, err
	}
	_ = setDF(handle)

	// create an established tcp connection
	// will hack this tcp connection for packet transmission
	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4194304)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4194304)
			})
		},
	}
	connInterface, err := dialer.Dial("tcp", raddr.String())
	if err != nil {
		return nil, err
	}
	tcpconn := connInterface.(*net.TCPConn)

	// fields
	conn := new(FakeTCPPacketConn)
	conn.die = make(chan struct{})
	conn.tcpconn = tcpconn
	conn.logger = l
	conn.debug = debug
	conn.chMessage = make(chan message, 65536)

	raddrTCP := tcpconn.RemoteAddr().(*net.TCPAddr)
	key := addrToKey(raddrTCP)
	e := conn.getFlow(key)
	e.conn.Store(tcpconn)
	conn.handles = append(conn.handles, handle)
	conn.SetReadBuffer(4194304)
	conn.SetWriteBuffer(4194304)
	go conn.captureFlow(handle, tcpconn.LocalAddr().(*net.TCPAddr).Port)

	// nftables
	err = setTTL(tcpconn, 1)
	if err != nil {
		return nil, err
	}

	conn.nftKey = nftRuleKey(nil, raddr.IP, 0, uint16(raddr.Port))
	conn.nftRule4, conn.nftRule6 = acquireNftRules(conn.nftKey, nil, raddr.IP, 0, uint16(raddr.Port))

	// discard everything
	go io.Copy(io.Discard, tcpconn)

	return conn, nil
}

// ListenPacket acts like net.ListenTCP,
// and returns a single packet-oriented connection.
// If bindInterface is non-empty, only capture on that network interface.
func ListenPacket(address string, bindInterface string, l logger.ContextLogger, debug bool) (*FakeTCPPacketConn, error) {
	addr := M.ParseSocksaddr(address)
	laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(addr.Addr.String(), fmt.Sprint(addr.Port)))
	if err != nil {
		return nil, err
	}

	// fields
	conn := new(FakeTCPPacketConn)
	conn.die = make(chan struct{})
	conn.logger = l
	conn.debug = debug
	conn.chMessage = make(chan message, 65536)

	// AF_INET
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	if laddr.IP == nil || laddr.IP.IsUnspecified() { // if address is not specified, capture on matching ifaces
		// Validate bind_interface exists if specified
		if bindInterface != "" {
			found := false
			for _, iface := range ifaces {
				if iface.Name == bindInterface {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("bind_interface %q not found", bindInterface)
			}
		}

		// Use unbound raw sockets for maximum compatibility.
		// Some cloud environments (e.g., Oracle Cloud ARM / virtio-net) don't
		// deliver TCP packet copies to raw sockets bound to specific IPs.
		// Port filtering in captureFlow ensures only relevant packets are processed.
		var lasterr error
		for _, proto := range []string{"ip4:tcp", "ip6:tcp"} {
			handle, err := net.ListenIP(proto, nil)
			if err != nil {
				if l != nil {
					l.Warn("[faketcp] failed to create raw socket (", proto, "): ", err)
				}
				lasterr = err
				continue
			}
			// Restrict to specific interface if requested
			if bindInterface != "" {
				if rawConn, err := handle.SyscallConn(); err == nil {
					var bindErr error
					rawConn.Control(func(fd uintptr) {
						bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, bindInterface)
					})
					if bindErr != nil && l != nil {
						l.Warn("[faketcp] SO_BINDTODEVICE failed for ", proto, ": ", bindErr)
					}
				}
			}
			if l != nil {
				l.Info("[faketcp] raw socket (", proto, ") started, bindInterface=", bindInterface)
			}
			_ = setDF(handle)
			conn.handles = append(conn.handles, handle)
			go conn.captureFlow(handle, laddr.Port)
		}
		if len(conn.handles) == 0 {
			return nil, lasterr
		}
	} else {
		if handle, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: laddr.IP}); err == nil {
			_ = setDF(handle)
			conn.handles = append(conn.handles, handle)
			go conn.captureFlow(handle, laddr.Port)
		} else {
			return nil, err
		}
	}

	// start listening
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4194304)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4194304)
			})
		},
	}
	lnInterface, err := lc.Listen(context.Background(), "tcp", laddr.String())
	if err != nil {
		return nil, err
	}
	tcpln := lnInterface.(*net.TCPListener)

	conn.listener = tcpln
	if l != nil {
		l.Info("faketcp server started at ", tcpln.Addr())
	}

	// start cleaner
	go conn.cleaner()

	// nftables drop packets marked with TTL = 1
	// TODO: what if nftables is not available, the next hop will send back ICMP Time Exceeded,
	// is this still an acceptable behavior?
	conn.nftKey = nftRuleKey(nil, nil, uint16(laddr.Port), 0)
	conn.nftRule4, conn.nftRule6 = acquireNftRules(conn.nftKey, nil, nil, uint16(laddr.Port), 0)

	// discard everything in original connection
	go func() {
		for {
			tcpconn, err := tcpln.AcceptTCP()
			if err != nil {
				return
			}

			// if we cannot set TTL = 1, the only thing reasonable is panic
			if err := setTTL(tcpconn, 1); err != nil {
				panic(err)
			}

			// record net.Conn
			raddrTCP := tcpconn.RemoteAddr().(*net.TCPAddr)
			key := addrToKey(raddrTCP)
			e := conn.getFlow(key)
			e.conn.Store(tcpconn)

			// discard everything
			go io.Copy(io.Discard, tcpconn)
		}
	}()

	conn.SetReadBuffer(4194304)
	conn.SetWriteBuffer(4194304)

	return conn, nil
}

// FakeTCPConn wraps a FakeTCPPacketConn as a net.Conn
type FakeTCPConn struct {
	packetConn *FakeTCPPacketConn
	remoteAddr net.Addr
	localAddr  net.Addr
	logger     logger.ContextLogger
}

func DialConn(remoteAddr string, l logger.ContextLogger, debug bool) (*FakeTCPConn, error) {
	pc, err := DialPacket(remoteAddr, l, debug)
	if err != nil {
		return nil, err
	}
	return &FakeTCPConn{
		packetConn: pc,
		remoteAddr: pc.tcpconn.RemoteAddr(),
		localAddr:  pc.LocalAddr(),
		logger:     l,
	}, nil
}

func (c *FakeTCPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.packetConn.ReadFrom(b)
	return
}

func (c *FakeTCPConn) Write(b []byte) (n int, err error) {
	n, err = c.packetConn.WriteTo(b, c.remoteAddr)
	return
}

func (c *FakeTCPConn) Close() error {
	return c.packetConn.Close()
}

func (c *FakeTCPConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *FakeTCPConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *FakeTCPConn) SetDeadline(t time.Time) error {
	return c.packetConn.SetDeadline(t)
}

func (c *FakeTCPConn) SetReadDeadline(t time.Time) error {
	return c.packetConn.SetReadDeadline(t)
}

func (c *FakeTCPConn) SetWriteDeadline(t time.Time) error {
	return c.packetConn.SetWriteDeadline(t)
}

// setTTL sets the Time-To-Live field on a given connection
func setTTL(c *net.TCPConn, ttl int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.TCPAddr)

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
	return err
}

// setDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
func setDSCP(c *net.IPConn, dscp int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.IPAddr)

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, dscp)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscp<<2)
		})
	}
	return err
}

// buildDropRuleIPv4 builds an nftables rule to drop IPv4 TCP packets with TTL=1.
// If srcIP or dstIP is nil, it skips matching that IP.
// If srcPort or dstPort is 0, it skips matching that port.
func buildDropRuleIPv4(srcIP, dstIP net.IP, srcPort, dstPort uint16) []expr.Any {
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 1}, // TTL
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
	}
	if srcIP != nil {
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // SrcIP
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: srcIP.To4()})
	}
	if dstIP != nil {
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, // DstIP
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dstIP.To4()})
	}
	if srcPort != 0 {
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2}, // SrcPort
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(srcPort >> 8), byte(srcPort)}})
	}
	if dstPort != 0 {
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, // DstPort
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(dstPort >> 8), byte(dstPort)}})
	}
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	return exprs
}

func buildDropRuleIPv6(srcIP, dstIP net.IP, srcPort, dstPort uint16) []expr.Any {
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1}, // Hop Limit
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
	}
	if srcIP != nil {
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}, // SrcIP
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: srcIP.To16()})
	}
	if dstIP != nil {
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}, // DstIP
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dstIP.To16()})
	}
	if srcPort != 0 {
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2}, // SrcPort
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(srcPort >> 8), byte(srcPort)}})
	}
	if dstPort != 0 {
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, // DstPort
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(dstPort >> 8), byte(dstPort)}})
	}
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	return exprs
}
