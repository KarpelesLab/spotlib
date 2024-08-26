package spotlib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/cryptutil"
)

// Client holds information about a client, including its connections to the spot servers
type Client struct {
	s       *ecdsa.PrivateKey // main signer for connection/etc
	id      *cryptutil.IDCard
	idBin   []byte // signed id
	kc      *cryptutil.Keychain
	conns   map[string]*conn
	connsLk sync.Mutex
	connCnt uint32
}

// New starts a new Client and establishes connection to the Spot system. If any key is passed,
// the first key will be used as the main signing key.
func New(keys ...any) (*Client, error) {
	c := &Client{
		kc:    cryptutil.NewKeychain(),
		conns: make(map[string]*conn),
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

func (c *Client) Logf(msg string, args ...any) {
	slog.Debug("spot client: "+fmt.Sprintf(msg, args...), "event", "spot:client")
}

func (c *Client) mainThread() {
	t := time.NewTicker(30 * time.Second)

	c.Logf("client entering main thread")

	err := c.runConnect()
	if err != nil {
		c.Logf("failed to perform initial connection: %s", err)
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
					c.Logf("failed to perform initial connection: %s", err)
				}
			}
		}
	}
}
