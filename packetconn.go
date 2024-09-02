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

type packetConnListener struct {
	c    *Client
	buf  chan *packetInfo
	name string
	rdl  time.Time // read deadline
	wdl  time.Time // write deadline
}

type packetInfo struct {
	body []byte
	addr net.Addr
}

// SpotAddr is a type implementing net.Addr that represents a spot address (typically, k:xxx/yyy)
type SpotAddr string

func (s SpotAddr) Network() string {
	return "spot"
}

func (s SpotAddr) String() string {
	return string(s)
}

// ListenPacket returns a [net.PacketConn] object that can be used to easily exchange
// encrypted packets with other peers without having to think about the underlying
// parts.
func (c *Client) ListenPacket(name string) (net.PacketConn, error) {
	res := &packetConnListener{
		c:    c,
		buf:  make(chan *packetInfo, 16),
		name: name,
	}

	c.SetHandler(name, res.handle)
	return res, nil
}

func (p *packetConnListener) handle(msg *spotproto.Message) ([]byte, error) {
	if !msg.IsEncrypted() {
		return nil, errors.New("invalid message: must be encrypted")
	}
	p.buf <- &packetInfo{body: msg.Body, addr: SpotAddr(msg.Sender)}
	return nil, nil
}

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

func (p *packetConnListener) Close() error {
	p.c.SetHandler(p.name, nil)
	close(p.buf)
	return nil
}

func (p *packetConnListener) LocalAddr() net.Addr {
	return SpotAddr(p.c.TargetId() + "/" + p.name)
}

func (p *packetConnListener) SetDeadline(t time.Time) error {
	p.rdl, p.wdl = t, t
	return nil
}

func (p *packetConnListener) SetReadDeadline(t time.Time) error {
	p.rdl = t
	return nil
}

func (p *packetConnListener) SetWriteDeadline(t time.Time) error {
	p.wdl = t
	return nil
}
