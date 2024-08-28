package spotlib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/spotproto"
	"github.com/google/uuid"
)

// Client holds information about a client, including its connections to the spot servers
type Client struct {
	s       *ecdsa.PrivateKey // main signer for connection/etc
	id      *cryptutil.IDCard
	idBin   []byte // signed id
	idLk    sync.Mutex
	kc      *cryptutil.Keychain
	mWrQ    chan *spotproto.Message // message write queue
	conns   map[string]*conn
	connsLk sync.Mutex
	connCnt uint32
	inQ     map[string]chan any
	inQLk   sync.Mutex
}

// New starts a new Client and establishes connection to the Spot system. If any key is passed,
// the first key will be used as the main signing key.
func New(keys ...any) (*Client, error) {
	c := &Client{
		kc:    cryptutil.NewKeychain(),
		conns: make(map[string]*conn),
		mWrQ:  make(chan *spotproto.Message, 4),
		inQ:   make(map[string]chan any),
	}

	// generate a new ecdsa private key
	var err error
	c.s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		keys = []any{c.s}
	}

	for _, k := range keys {
		if err := c.kc.AddKey(k); err != nil {
			return nil, fmt.Errorf("invalid key (type=%T): %w", k, err)
		}
	}

	// this shouldn't fail at this point since the keys added successfully to the keychain, but check anyway just in case
	pub := cryptutil.PublicKey(keys[0])
	if pub == nil {
		return nil, fmt.Errorf("bad key type %T", keys[0])
	}

	// generate a client ID
	c.id, err = cryptutil.NewIDCard(pub)
	if err != nil {
		return nil, err
	}
	c.id.AddKeychain(c.kc)

	// sign the ID
	c.idBin, err = c.id.Sign(rand.Reader, keys[0].(crypto.Signer))
	if err != nil {
		return nil, err
	}

	// start the connection thread
	go c.mainThread()

	return c, nil
}

// Query sends a request & waits for the response
func (c *Client) Query(target string, body []byte) ([]byte, error) {
	id := uuid.New()
	ch := c.makeInQ(id.String())
	defer c.takeInQ(id.String())

	msg := &spotproto.Message{
		MessageID: id,
		Recipient: target,
		Body:      body,
	}

	c.mWrQ <- msg

	t := time.NewTimer(2 * time.Second) // timeout for response

	select {
	case <-t.C:
		// time out
		return nil, errors.New("request timeout")
	case v := <-ch:
		// got a response
		switch obj := v.(type) {
		case []byte:
			return obj, nil
		case *spotproto.Message:
			return obj.Body, nil
		default:
			return nil, fmt.Errorf("invalid message response type %T", v)
		}
	}
}

func (c *Client) logf(msg string, args ...any) {
	slog.Debug("spot client: "+fmt.Sprintf(msg, args...), "event", "spot:client")
}

func (c *Client) mainThread() {
	t := time.NewTicker(30 * time.Second)

	c.logf("client entering main thread")

	err := c.runConnect()
	if err != nil {
		c.logf("failed to perform initial connection: %s", err)
	}

	for {
		select {
		case <-t.C:
			// perform checks like number of connections, etc
			cnt := atomic.LoadUint32(&c.connCnt)
			if cnt < 1 {
				// need to establish connections
				err := c.runConnect()
				if err != nil {
					c.logf("failed to perform initial connection: %s", err)
				}
			}
		}
	}
}

func (c *Client) handleGroups(groups [][]byte) error {
	c.idLk.Lock()
	defer c.idLk.Unlock()

	err := c.id.UpdateGroups(groups)
	if err != nil {
		return err
	}

	// re-sign
	key, err := c.kc.GetSigner(c.id.Self)
	if err != nil {
		return err
	}
	idBin, err := c.id.Sign(rand.Reader, key)
	if err != nil {
		return err
	}
	c.idBin = idBin
	return nil

}

func (c *Client) makeInQ(key string) chan any {
	ch := make(chan any, 1)

	c.inQLk.Lock()
	defer c.inQLk.Unlock()

	c.inQ[key] = ch
	return ch
}

func (c *Client) takeInQ(key string) chan any {
	c.inQLk.Lock()
	defer c.inQLk.Unlock()

	if v, ok := c.inQ[key]; ok {
		delete(c.inQ, key)
		return v
	}
	return nil
}
