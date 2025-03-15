// Package spotlib provides a client implementation for the Spot secure messaging protocol
package spotlib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/KarpelesLab/spotproto"
)

// packetConnListener implements the net.PacketConn interface for Spot messaging
type packetConnListener struct {
	c    *Client          // Reference to the parent client
	buf  chan *packetInfo // Channel buffer for received packets
	name string           // Endpoint name for receiving messages
	rdl  time.Time        // Read deadline
	wdl  time.Time        // Write deadline
}

// packetInfo holds information about a received packet
type packetInfo struct {
	body []byte   // Packet payload
	addr net.Addr // Source address
}

// SpotAddr is a type implementing net.Addr that represents a spot address (typically, k.xxx/yyy)
// This allows using standard Go networking patterns with the Spot protocol
type SpotAddr string

// Network returns the name of the network ("spot")
func (s SpotAddr) Network() string {
	return "spot"
}

// String returns the address as a string
func (s SpotAddr) String() string {
	return string(s)
}

// ListenPacket returns a net.PacketConn object that can be used to easily exchange
// encrypted packets with other peers without having to think about the underlying
// protocol details.
//
// The name parameter defines the endpoint that will receive messages.
// Messages are automatically encrypted and signatures are verified.
func (c *Client) ListenPacket(name string) (net.PacketConn, error) {
	res := &packetConnListener{
		c:    c,
		buf:  make(chan *packetInfo, 16),
		name: name,
	}

	c.SetHandler(name, res.handle)
	return res, nil
}

// handle is a message handler that processes incoming packets and adds them to the buffer
func (p *packetConnListener) handle(msg *spotproto.Message) ([]byte, error) {
	if !msg.IsEncrypted() {
		return nil, errors.New("invalid message: must be encrypted")
	}
	p.buf <- &packetInfo{body: msg.Body, addr: SpotAddr(msg.Sender)}
	return nil, nil
}

// ReadFrom implements the net.PacketConn interface for receiving packets
// It returns the packet contents, sender address, and any error encountered
func (p *packetConnListener) ReadFrom(buf []byte) (int, net.Addr, error) {
	var stopCh <-chan time.Time
	if !p.rdl.IsZero() {
		d := time.Until(p.rdl)
		if d <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		stopCh = t.C
	}

	select {
	case pkt, ok := <-p.buf:
		if !ok {
			return 0, nil, io.EOF
		}
		n := copy(buf, pkt.body)
		return n, pkt.addr, nil
	case <-stopCh:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

// WriteTo implements the net.PacketConn interface for sending packets
// It encrypts and sends the data to the specified address
func (p *packetConnListener) WriteTo(buf []byte, addr net.Addr) (int, error) {
	// write message
	addrS, ok := addr.(SpotAddr)
	if !ok {
		return 0, fmt.Errorf("invalid spot target type %T", addr)
	}

	ctx := context.Background()
	if !p.wdl.IsZero() {
		var cancel func()
		ctx, cancel = context.WithDeadline(ctx, p.wdl)
		defer cancel()
	}
	err := p.c.SendToWithFrom(ctx, string(addrS), buf, "/"+p.name)
	if err != nil {
		return 0, err
	}
	return len(buf), nil
}

// Close implements the net.PacketConn interface for shutting down the connection
// It unregisters the message handler and closes the buffer channel
func (p *packetConnListener) Close() error {
	p.c.SetHandler(p.name, nil)
	close(p.buf)
	return nil
}

// LocalAddr implements the net.PacketConn interface to return the local endpoint address
func (p *packetConnListener) LocalAddr() net.Addr {
	return SpotAddr(p.c.TargetId() + "/" + p.name)
}

// SetDeadline implements the net.PacketConn interface to set both read and write deadlines
func (p *packetConnListener) SetDeadline(t time.Time) error {
	p.rdl, p.wdl = t, t
	return nil
}

// SetReadDeadline implements the net.PacketConn interface to set the read deadline
func (p *packetConnListener) SetReadDeadline(t time.Time) error {
	p.rdl = t
	return nil
}

// SetWriteDeadline implements the net.PacketConn interface to set the write deadline
func (p *packetConnListener) SetWriteDeadline(t time.Time) error {
	p.wdl = t
	return nil
}
