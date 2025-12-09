package spotlib

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/rest"
	"github.com/KarpelesLab/spotproto"
	"github.com/coder/websocket"
)

// conn represents a single connection to a Spot server
type conn struct {
	host string      // hostname of the spot server
	wr   chan []byte // write channel for sending raw binary packets
	c    *Client     // reference to the parent client
}

// getConn retrieves an existing connection to the specified host or returns nil if none exists
func (c *Client) getConn(host string) *conn {
	c.connsLk.Lock()
	defer c.connsLk.Unlock()

	if v, ok := c.conns[host]; ok {
		return v
	}
	return nil
}

// regConn registers a new connection in the client's connection map
func (c *Client) regConn(co *conn) {
	c.connsLk.Lock()
	defer c.connsLk.Unlock()

	c.conns[co.host] = co
}

// unregConn removes a connection from the client's connection map
// Returns true if the connection was found and removed, false otherwise
func (c *Client) unregConn(co *conn) bool {
	c.connsLk.Lock()
	defer c.connsLk.Unlock()

	if v, ok := c.conns[co.host]; ok && v == co {
		delete(c.conns, co.host)
		return true
	}
	return false
}

// getHosts retrieves a list of available Spot servers from the API
// Returns a list of host addresses and the minimum recommended connection count
func getHosts(ctx context.Context) ([]string, uint32, error) {
	// call Spot:connect API to fetch hosts we can connect to
	var res *struct {
		Hosts   []string `json:"hosts"`
		MinConn uint32   `json:"min_conn"`
	}
	err := rest.Apply(ctx, "Spot:connect", "GET", nil, &res)
	if err != nil {
		return nil, 0, err
	}
	return res.Hosts, res.MinConn, nil
}

// runConnect establishes connections to Spot servers
// Fetches available hosts and creates connections as needed to meet minimum requirements
func (c *Client) runConnect() error {
	hosts, minConn, err := getHosts(context.Background())
	if err != nil {
		return err
	}
	if minConn == 0 {
		minConn = uint32(len(hosts))
	}
	if len(hosts) > 10 {
		hosts = hosts[:10]
	}
	c.minConn = minConn

	for _, h := range hosts {
		if c.getConn(h) == nil {
			c.logf("connecting to host: %s", h)
			co := &conn{
				host: h,
				c:    c,
				wr:   make(chan []byte),
			}
			c.regConn(co)
			go co.run()
			// delay things a bit so we don't perform too many handshakes at the same time
			time.Sleep(2 * time.Second)
		}
	}

	return nil
}

// run manages the connection lifecycle, handling reconnection and cleanup
// This function runs in its own goroutine for each connection
func (co *conn) run() {
	defer co.c.unregConn(co)

	atomic.AddUint32(&co.c.connCnt, 1)
	defer atomic.AddUint32(&co.c.connCnt, ^uint32(0))

	failGiveup := 0

	for atomic.LoadUint32(&co.c.closed) == 0 {
		c, err := co.dial()
		if err != nil {
			co.c.logf("failed to connect to server: %s", err)
			failGiveup += 1
			if failGiveup > 10 {
				// give up so we can have a better connection later
				return
			}
			time.Sleep(2 * time.Second)
			continue
		}

		failGiveup = 0

		err = co.handle(c)
		if err != nil {
			if err != io.EOF {
				co.c.logf("error during communications with server: %s", err)
			}
		}
		// retry connection immediately
	}
}

// handle manages an established websocket connection
// Performs handshake and then handles message routing in a continuous loop
func (co *conn) handle(c *websocket.Conn) error {
	defer c.CloseNow()
	c.SetReadLimit(1024 * 1024) // 1MB max packet size

	if err := co.handshake(c); err != nil {
		return err
	}

	co.c.onlineIncr()
	defer co.c.onlineDecr()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go co.handleWrites(ctx, cancel, c)

	for {
		mt, dat, err := c.Read(ctx)
		if err != nil {
			return fmt.Errorf("while reading packet: %w", err)
		}

		switch mt {
		case websocket.MessageBinary:
			err = co.handlePacket(dat)
			if err != nil {
				return err
			}
		case websocket.MessageText:
			// TODO handle text messages. For now we do nothing of these
		}
	}
}

// handleWrites runs in a separate goroutine to handle outgoing messages
// Monitors channels for messages to send and forwards them to the websocket
func (co *conn) handleWrites(ctx context.Context, cancel func(), wsc *websocket.Conn) {
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case _, _ = <-co.c.alive:
			return
		case msg := <-co.c.mWrQ:
			// write message
			buf := msg.Bytes()
			buf = append([]byte{spotproto.InstantMsg}, buf...)
			wsc.Write(ctx, websocket.MessageBinary, buf)
		case buf := <-co.wr:
			wsc.Write(ctx, websocket.MessageBinary, buf)
		}
	}
}

// handshake performs the authentication handshake with the Spot server
// Processes challenges, handles group membership, and sends client identity information
func (co *conn) handshake(c *websocket.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	for {
		mt, dat, err := c.Read(ctx)
		if err != nil {
			return fmt.Errorf("while reading packet: %w", err)
		}

		switch mt {
		case websocket.MessageBinary:
			pkt, err := spotproto.Parse(dat, true)
			if err != nil {
				return fmt.Errorf("parse error: %w", err)
			}

			switch obj := pkt.(type) {
			case *spotproto.HandshakeRequest:
				if obj.Ready {
					co.c.logf("authentication done, connected as c.%s", obj.ClientId)
					return nil
				}
				if obj.Groups != nil {
					// need to re-compute key
					co.c.handleGroups(obj.Groups)
				}
				// generate response
				res, err := obj.Respond(nil, co.c.s)
				if err != nil {
					return err
				}
				res.ID = co.c.idBin
				// send
				buf := append([]byte{spotproto.Handshake}, res.Bytes()...)
				c.Write(ctx, websocket.MessageBinary, buf)
			default:
				co.c.logf("unsupported handshake packet type %T", obj)
			}
		case websocket.MessageText:
			// TODO handle text messages. For now we do nothing of these
		}
	}
}

// dial establishes a websocket connection to the Spot server
func (co *conn) dial() (*websocket.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	u := "wss://" + co.host + "/_websocket"

	co.c.logf("dialing via websocket: %s", u)

	// Create a custom HTTP client with our g-dns.net resolver to avoid
	// DNS lookup issues with misconfigured DNS servers
	resolver := newGdnsResolver()
	transport := &http.Transport{
		DialContext: resolver.Dial,
		TLSClientConfig: &tls.Config{
			ServerName: co.host,
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// First establish a plain TCP connection using our resolver
			conn, err := resolver.Dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			// Then wrap it with TLS
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName: co.host,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	httpClient := &http.Client{Transport: transport}

	opts := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	c, _, err := websocket.Dial(ctx, u, opts)
	return c, err
}

// handlePacket processes an incoming binary packet from the server
// Parses the packet and routes it appropriately based on type and content
func (co *conn) handlePacket(dat []byte) error {
	pkt, err := spotproto.Parse(dat, true)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	switch obj := pkt.(type) {
	case *spotproto.HandshakeRequest:
		if obj.Ready {
			return nil
		}
		if obj.Groups != nil {
			// need to re-compute key
			co.c.handleGroups(obj.Groups)
		}
		// generate response
		res, err := obj.Respond(nil, co.c.s)
		if err != nil {
			return err
		}
		res.ID = co.c.idBin
		// send
		buf := append([]byte{spotproto.Handshake}, res.Bytes()...)
		co.wr <- buf
		return nil
	case *spotproto.Message:
		// Recipient:c:4p84:conn-ubzvcl-h7yv-g7pe-tfp6-mddcsqtu/699ec197-d329-45bd-9306-b29f2ff99ac9
		rcv := obj.Recipient
		pos := strings.IndexByte(rcv, '/')
		if pos == -1 {
			return nil
		}
		rcv = rcv[pos+1:]
		if pos2 := strings.IndexByte(rcv, '/'); pos2 != -1 {
			rcv = rcv[:pos2]
		}

		q := co.c.takeInQ(rcv)
		if q != nil {
			q <- obj
		} else if h := co.c.getHandler(rcv); h != nil {
			go co.c.runHandler(obj, h)
		} else {
			co.c.logf("unable to route packet targetted to %s", obj.Recipient)
		}
		return nil
	default:
		co.c.logf("unsupported packet type %T", obj)
		return nil
	}
}
