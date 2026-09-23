//go:build !linux
// +build !linux

package faketcp

import (
	"errors"
	"net"
	"time"

	"github.com/sagernet/sing/common/logger"
)

var errUnsupported = errors.New("faketcp is only supported on linux")

type FakeTCPPacketConn struct{}

func ListenPacket(address string, bindInterface string, l logger.ContextLogger, debug bool) (*FakeTCPPacketConn, error) {
	return nil, errUnsupported
}

func DialPacket(remoteAddr string, l logger.ContextLogger, debug bool) (*FakeTCPPacketConn, error) {
	return nil, errUnsupported
}

func (c *FakeTCPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, errUnsupported
}

func (c *FakeTCPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, errUnsupported
}

func (c *FakeTCPPacketConn) Close() error { return nil }

func (c *FakeTCPPacketConn) LocalAddr() net.Addr { return nil }

func (c *FakeTCPPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *FakeTCPPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *FakeTCPPacketConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *FakeTCPPacketConn) SetDSCP(dscp int) error             { return nil }
func (c *FakeTCPPacketConn) SetReadBuffer(bytes int) error      { return nil }
func (c *FakeTCPPacketConn) SetWriteBuffer(bytes int) error     { return nil }
func (c *FakeTCPPacketConn) SyscallConn() (interface{}, error)  { return nil, errUnsupported }

type FakeTCPConn struct{}

func DialConn(remoteAddr string, l logger.ContextLogger, debug bool) (*FakeTCPConn, error) {
	return nil, errUnsupported
}

func (c *FakeTCPConn) Read(b []byte) (n int, err error)  { return 0, errUnsupported }
func (c *FakeTCPConn) Write(b []byte) (n int, err error) { return 0, errUnsupported }
func (c *FakeTCPConn) Close() error                      { return nil }
func (c *FakeTCPConn) LocalAddr() net.Addr               { return nil }
func (c *FakeTCPConn) RemoteAddr() net.Addr              { return nil }
func (c *FakeTCPConn) SetDeadline(t time.Time) error     { return nil }
func (c *FakeTCPConn) SetReadDeadline(t time.Time) error { return nil }
func (c *FakeTCPConn) SetWriteDeadline(t time.Time) error {
	return nil
}
