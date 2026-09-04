package faketcp

import "net"

// pseudoHeaderChecksum calculates the IPv4/IPv6 pseudo-header checksum (without folding)
func pseudoHeaderChecksum(srcIP, dstIP net.IP, isIPv6 bool) uint32 {
	var csum uint32
	if isIPv6 {
		for i := 0; i < 16; i += 2 {
			csum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
			csum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
		}
		csum += 6 // NextHeader
	} else {
		src := srcIP.To4()
		dst := dstIP.To4()
		if src != nil && dst != nil {
			csum += uint32(src[0])<<8 | uint32(src[1])
			csum += uint32(src[2])<<8 | uint32(src[3])
			csum += uint32(dst[0])<<8 | uint32(dst[1])
			csum += uint32(dst[2])<<8 | uint32(dst[3])
		}
		csum += 6 // Protocol
	}
	return csum
}

// fastTCPChecksum uses the cached pseudo-header checksum and quickly sums the payload
func fastTCPChecksum(pseudoSum uint32, tcpLen uint16, tcpHdr []byte, payload []byte) uint16 {
	csum := pseudoSum + uint32(tcpLen)

	// TCP header
	for i := 0; i < 20; i += 2 {
		if i == 16 { // Skip checksum field itself
			continue
		}
		csum += uint32(tcpHdr[i])<<8 | uint32(tcpHdr[i+1])
	}

	// Payload
	payloadLen := len(payload)
	for i := 0; i < payloadLen-1; i += 2 {
		csum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if payloadLen%2 == 1 {
		csum += uint32(payload[payloadLen-1]) << 8
	}

	csum = (csum >> 16) + (csum & 0xffff)
	csum += csum >> 16
	return ^uint16(csum)
}
