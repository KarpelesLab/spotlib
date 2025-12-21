package spotlib

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/emitter"
	"github.com/KarpelesLab/spotproto"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// Client holds information about a client, including its connections to the spot servers.
// It manages cryptographic identity, connection state, message handlers, and provides
// high-level methods for secure communication through the Spot protocol.
type Client struct {
	s           crypto.Signer             // main signer for connection/authentication
	Events      *emitter.Hub              // event hub for client events (online, offline, etc.)
	id          *gobottle.IDCard          // client identity card
	idBin       []byte                    // binary representation of signed identity
	idLk        sync.Mutex                // mutex for ID operations
	kc          *gobottle.Keychain        // keychain for crypto operations
	mWrQ        chan *spotproto.Message   // message write queue for outgoing messages
	conns       map[string]*conn          // active connections to spot servers
	connsLk     sync.Mutex                // mutex for connections map access
	minConn     uint32                    // minimum number of connections to maintain
	connCnt     uint32                    // total connection count
	onlineCnt   uint32                    // number of online connections (past handshake)
	onlineCntLk sync.RWMutex              // mutex for online count operations
	inQ         map[string]chan any       // inbound message queues by message ID
	inQLk       sync.Mutex                // mutex for inQ map access
	msghdlr     map[string]MessageHandler // registered message handlers by endpoint
	msghdlrLk   sync.RWMutex              // mutex for message handler operations
	idCache     map[string]*idCacheEntry  // cache of remote identity cards
	idCacheLk   sync.RWMutex              // mutex for ID cache operations
	alive       chan struct{}             // channel closed when client is shut down
	closed      uint32                    // atomic flag indicating client is closed
}

// New starts a new Client and establishes connection to the Spot system. If any key is passed,
// the first key will be used as the main signing key.
//
// Parameters can include:
// - gobottle.PrivateKey or *gobottle.Keychain: keys to use for signing/encryption
// - *emitter.Hub: event hub to use instead of creating a new one
// - map[string]MessageHandler: initial message handlers to register
// - map[string]string: metadata to include in the client ID card
func New(params ...any) (*Client, error) {
	c := &Client{
		Events:  emitter.New(),
		kc:      gobottle.NewKeychain(),
		minConn: 1,
		conns:   make(map[string]*conn),
		mWrQ:    make(chan *spotproto.Message, 4),
		inQ:     make(map[string]chan any),
		msghdlr: make(map[string]MessageHandler),
		idCache: make(map[string]*idCacheEntry),
		alive:   make(chan struct{}),
	}
	c.setDefaultHandlers()

	// generate a new ecdsa private key
	var err error
	meta := make(map[string]string)

	for _, p := range params {
		switch v := p.(type) {
		case *gobottle.Keychain:
			c.kc.AddKey(v)
		case gobottle.PrivateKey:
			c.kc.AddKey(v)
		case *emitter.Hub:
			c.Events = v
		case map[string]MessageHandler:
			for ep, h := range v {
				c.msghdlr[ep] = h
			}
		case map[string]string:
			for k, s := range v {
				meta[k] = s
			}
		default:
			return nil, fmt.Errorf("unsupported parameter type %T", p)
		}
	}

	for k := range c.kc.All {
		switch s := k.(type) {
		case *ecdsa.PrivateKey:
			c.s = s
		case *rsa.PrivateKey:
			c.s = s
		}
	}

	ephemeral := false
	if c.s == nil {
		c.s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		c.kc.AddKey(c.s)
		ephemeral = true
	}

	// this shouldn't fail at this point since the keys added successfully to the keychain, but check anyway just in case
	pub := gobottle.PublicKey(c.kc.FirstSigner())
	if pub == nil {
		return nil, fmt.Errorf("bad key type %T", c.kc.FirstSigner())
	}

	// generate a client ID
	c.id, err = gobottle.NewIDCard(pub)
	if err != nil {
		return nil, err
	}
	c.id.Meta = meta
	c.id.AddKeychain(c.kc)

	if ephemeral {
		c.id.AddKeyPurpose(c.s.Public(), "ephemeral")
	}

	// sign the ID
	c.idBin, err = c.id.Sign(rand.Reader, c.kc.FirstSigner())
	if err != nil {
		return nil, err
	}

	// start the connection thread
	go c.mainThread()

	return c, nil
}

// Close gracefully shuts down the client and all its connections.
// This method is idempotent and safe to call multiple times.
func (c *Client) Close() error {
	if atomic.AddUint32(&c.closed, 1) == 1 {
		close(c.alive)
		c.alive = nil
	}
	return nil
}

// IDCard returns the client's own identity card containing its public key and metadata
func (c *Client) IDCard() *gobottle.IDCard {
	return c.id
}

// TargetId returns the local client ID in the format 'k.<base64hash>'
// that can be used to transmit messages to this client
func (c *Client) TargetId() string {
	return "k." + base64.RawURLEncoding.EncodeToString(gobottle.Hash(c.id.Self, sha256.New))
}

// ConnectionCount returns the number of spot server connections, and the number of
// said connections which are online (ie. past the handshake step).
func (c *Client) ConnectionCount() (uint32, uint32) {
	return atomic.LoadUint32(&c.connCnt), atomic.LoadUint32(&c.onlineCnt)
}

// Query sends a request & waits for the response. If the target is a key (starts with k.) the
// message will be encrypted & signed so only the recipient can open it.
//
// This is a blocking call that returns the response body or an error. The context can be used
// to set a timeout or cancel the operation.
func (c *Client) Query(ctx context.Context, target string, body []byte) ([]byte, error) {
	if len(target) == 0 {
		return nil, errors.New("invalid target")
	}

	var rid *gobottle.IDCard
	var err error

	switch target[0] {
	case 'k':
		// encrypt
		rid, err = c.GetIDCardForRecipient(ctx, target)
		if err != nil {
			return nil, err
		}
		body, err = c.prepareMessage(rid, body)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare query message: %w", err)
		}
	default:
		// sign only
		body, err = c.prepareMessage(rid, body)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare query message: %w", err)
		}
	}

	id := uuid.New()
	ch := c.makeInQ(id.String())
	defer c.takeInQ(id.String())

	msg := &spotproto.Message{
		MessageID: id,
		Sender:    "/" + id.String(),
		Recipient: target,
		Body:      body,
	}

	select {
	case c.mWrQ <- msg:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case <-ctx.Done():
		// time out?
		return nil, ctx.Err()
	case v := <-ch:
		// got a response
		switch obj := v.(type) {
		case *spotproto.Message:
			if obj.Flags&spotproto.MsgFlagNotBottle == 0 {
				// decode/decrypt message
				obj.Body, err = c.decodeMessage(rid, obj.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to decode response: %w", err)
				}
			} else if rid != nil {
				// if rid was not nil, the response must be an encrypted bottle
				return nil, fmt.Errorf("remote failed to respond with an encrypted response")
			}
			if obj.Flags&spotproto.MsgFlagError != 0 {
				return nil, errors.New(string(obj.Body))
			}
			return obj.Body, nil
		default:
			return nil, fmt.Errorf("invalid message response type %T", v)
		}
	}
}

// QueryTimeout calls Query with the specified timeout duration as a convenience wrapper
func (c *Client) QueryTimeout(timeout time.Duration, target string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.Query(ctx, target, body)
}

// GetGroupMembers retrieves a list of member IDs for the specified group key
func (c *Client) GetGroupMembers(ctx context.Context, groupKey []byte) ([]string, error) {
	buf, err := c.Query(ctx, "@/group_list", groupKey)
	if err != nil {
		return nil, err
	}

	var res []string
	for h := range slices.Chunk(buf, 32) {
		res = append(res, "k."+base64.RawURLEncoding.EncodeToString(h))
	}

	return res, nil
}

// StoreBlob stores the given value under the given key after encrypting it in a way that
// can only be retrieved by this client specifically, using the same private key. This can
// be useful to store some settings local to the node that may need to be re-obtained,
// however this method is to be considered best-effort and shouldn't be used for intensive
// storage activity. Note also that value will have a limit of slightly less than 49kB.
//
// Data may also be purged after some time without access.
func (c *Client) StoreBlob(ctx context.Context, key string, value []byte) error {
	if len(value) == 0 {
		// handle this as a delete
		_, err := c.Query(ctx, "@/store_blob", []byte(key+"\x00"))
		return err
	}
	b := gobottle.NewBottle(value)
	err := b.Encrypt(rand.Reader, c.id)
	if err != nil {
		return err
	}
	b.BottleUp()
	var sigErr error
	var sigCnt int
	for signer := range c.kc.Signers {
		if err = b.Sign(rand.Reader, signer); err != nil {
			sigErr = err
		} else {
			sigCnt += 1
		}
	}
	if sigCnt == 0 {
		if sigErr == nil {
			sigErr = errors.New("no signature key was available")
		}
		return fmt.Errorf("could not sign blob: %w", sigErr)
	}
	// cbor encode
	buf, err := cbor.Marshal(b)
	if err != nil {
		return err
	}
	// store
	_, err = c.Query(ctx, "@/store_blob", append([]byte(key+"\x00"), buf...))
	return err
}

// FetchBlob fetches a blob previously stored with StoreBlob. The operation can be
// slow and is provided as best effort. The data will be decrypted and verified.
func (c *Client) FetchBlob(ctx context.Context, key string) ([]byte, error) {
	buf, err := c.Query(ctx, "@/fetch_blob", []byte(key))
	if err != nil {
		return nil, err
	}
	op, err := gobottle.NewOpener(c.kc)
	if err != nil {
		return nil, err
	}
	data, info, err := op.OpenCbor(buf)
	if err != nil {
		return nil, err
	}
	if !info.SignedBy(c.id) {
		return nil, errors.New("data was not signed by us")
	}
	if info.Decryption == 0 {
		return nil, errors.New("data was not encrypted")
	}

	return data, nil
}

// GetIDCardBin returns the binary ID card for the given hash
// This also automatically subscribes the client to updates for this ID card
func (c *Client) GetIDCardBin(ctx context.Context, h []byte) ([]byte, error) {
	return c.Query(ctx, "@/idcard_find", h)
}

// GetIDCard returns the ID card for the given hash
// It first checks the local cache, and if not found, fetches it from the server.
// Also automatically subscribes to updates for this ID card.
func (c *Client) GetIDCard(ctx context.Context, h []byte) (*gobottle.IDCard, error) {
	if obj := c.getIDCardFromCache(h); obj != nil {
		return obj, nil
	}
	buf, err := c.GetIDCardBin(ctx, h)
	if err != nil {
		return nil, err
	}
	idc := &gobottle.IDCard{}
	err = idc.UnmarshalBinary(buf)
	if err != nil {
		return nil, err
	}

	// Store in cache
	c.setIDCardCache(h, idc)

	return idc, nil
}

// GetIDCardForRecipient returns the ID Card of a given recipient, if any
func (c *Client) GetIDCardForRecipient(ctx context.Context, rcv string) (*gobottle.IDCard, error) {
	// rcv has the format: k.<base64url hash>/<endpoint>
	if pos := strings.IndexByte(rcv, '/'); pos > 0 {
		rcv = rcv[:pos]
	}
	rcvA := strings.Split(rcv, ".")
	if len(rcvA) == 1 || rcvA[0] != "k" {
		return nil, fmt.Errorf("invalid recipient %s", rcv)
	}
	h, err := base64.RawURLEncoding.DecodeString(rcvA[len(rcvA)-1])
	if err != nil {
		return nil, err
	}
	return c.GetIDCard(ctx, h)
}

// GetTime queries the Spot server for its current time.
// This can be used for clock synchronization or to verify server connectivity.
func (c *Client) GetTime(ctx context.Context) (time.Time, error) {
	res, err := c.Query(ctx, "@/time", nil)
	if err != nil {
		return time.Time{}, err
	}
	if len(res) < 12 {
		return time.Time{}, errors.New("unable to parse time from server")
	}
	u := binary.BigEndian.Uint64(res[:8])
	n := binary.BigEndian.Uint32(res[8:12])
	return time.Unix(int64(u), int64(n)), nil
}

// prepareMessage prepares a message for sending by encrypting (if rid is not nil) and signing it
// Returns the CBOR-encoded message bottle ready for transmission
func (c *Client) prepareMessage(rid *gobottle.IDCard, payload []byte) ([]byte, error) {
	bottle := gobottle.NewBottle(payload)
	if rid != nil {
		err := bottle.Encrypt(rand.Reader, rid)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt message: %w", err)
		}
		bottle.BottleUp()
	}
	err := bottle.Sign(rand.Reader, c.s)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	body, err := cbor.Marshal(bottle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bottle: %w", err)
	}

	return body, nil
}

// decodeMessage decrypts and verifies a received message
// If rid is provided, verifies the message was signed by the expected sender
func (c *Client) decodeMessage(rid *gobottle.IDCard, payload []byte) ([]byte, error) {
	// need to decrypt this bottle
	bottle := gobottle.AsCborBottle(payload)
	buf, info, err := gobottle.MustOpener(c.kc).Open(bottle)
	if err != nil {
		return nil, fmt.Errorf("failed to open bottle: %w", err)
	}
	if rid != nil {
		if info.Decryption == 0 {
			return nil, errors.New("incoming message is not encrypted")
		}
		if !info.SignedBy(rid) {
			c.needKeyRefresh()
			return nil, errors.New("incoming message is not signed by sender")
		}
	}
	return buf, nil
}

// SendTo encrypts and sends a payload to the given target
func (c *Client) SendTo(ctx context.Context, target string, payload []byte) error {
	return c.SendToWithFrom(ctx, target, payload, "")
}

// SendToWithFrom encrypts and sends a payload to the given target, with the option to set the sender endpoint
func (c *Client) SendToWithFrom(ctx context.Context, target string, payload []byte, from string) error {
	rid, err := c.GetIDCardForRecipient(ctx, target)
	if err != nil {
		return fmt.Errorf("failed to find recipient: %w", err)
	}

	body, err := c.prepareMessage(rid, payload)
	if err != nil {
		return fmt.Errorf("failed to prepare message: %w", err)
	}

	id := uuid.New()

	if from == "" {
		from = "/" + id.String()
	}
	if from[0] != '/' {
		return errors.New("invalid from address for packet")
	}

	msg := &spotproto.Message{
		MessageID: id,
		Flags:     0,
		Sender:    from,
		Recipient: target,
		Body:      body,
	}

	c.mWrQ <- msg
	return nil
}

// logf logs debug messages with standard prefix and consistent formatting
func (c *Client) logf(msg string, args ...any) {
	slog.Debug("spot client: "+fmt.Sprintf(msg, args...), "event", "spot:client")
}

// mainThread runs as a goroutine and manages client lifecycle, including connection maintenance
func (c *Client) mainThread() {
	t := time.NewTicker(30 * time.Second)

	c.logf("client entering main thread")

	err := c.runConnect()
	if err != nil {
		c.logf("failed to perform initial connection: %s", err)
	}

	for range t.C {
		// perform checks like number of connections, etc
		cnt := atomic.LoadUint32(&c.connCnt)
		if cnt < c.minConn {
			// require at least 2 active connections
			err := c.runConnect()
			if err != nil {
				c.logf("failed to perform initial connection: %s", err)
			}
		}
	}
}

// handleGroups updates the client's group membership and re-signs the ID card
func (c *Client) handleGroups(groups [][]byte) error {
	c.idLk.Lock()
	defer c.idLk.Unlock()

	err := c.id.UpdateGroups(groups)
	if err != nil {
		return err
	}

	// re-sign
	idBin, err := c.id.Sign(rand.Reader, c.kc.FirstSigner())
	if err != nil {
		return err
	}
	c.idBin = idBin
	return nil

}

// makeInQ creates a new inbound message queue for the given key (typically a message ID)
func (c *Client) makeInQ(key string) chan any {
	ch := make(chan any, 1)

	c.inQLk.Lock()
	defer c.inQLk.Unlock()

	c.inQ[key] = ch
	return ch
}

// takeInQ removes and returns the inbound message queue for the given key
func (c *Client) takeInQ(key string) chan any {
	c.inQLk.Lock()
	defer c.inQLk.Unlock()

	if v, ok := c.inQ[key]; ok {
		delete(c.inQ, key)
		return v
	}
	return nil
}

// onlineIncr increments the online connection counter and triggers events if transitioning from offline to online
func (c *Client) onlineIncr() {
	c.onlineCntLk.Lock()
	defer c.onlineCntLk.Unlock()
	c.onlineCnt += 1
	if c.onlineCnt == 1 {
		// we went from 0 to 1, emit event
		go c.Events.EmitTimeout(15*time.Second, "status", 1, c.onlineCnt, atomic.LoadUint32(&c.connCnt))
		c.Events.Push("online")
	}
}

// onlineDecr decrements the online connection counter and triggers events if transitioning from online to offline
func (c *Client) onlineDecr() {
	c.onlineCntLk.Lock()
	defer c.onlineCntLk.Unlock()

	c.onlineCnt -= 1
	if c.onlineCnt == 0 {
		// we went offline, emit event
		go c.Events.EmitTimeout(15*time.Second, "status", 0, c.onlineCnt, atomic.LoadUint32(&c.connCnt))
	}
}

// WaitOnline waits for the client to establish at least one online connection
// Returns immediately if already online, otherwise blocks until online or context cancellation
func (c *Client) WaitOnline(ctx context.Context) error {
	l := c.Events.Trigger("online").Listen()
	defer l.Release()

	if c.onlineCnt > 0 {
		return nil
	}

	for {
		select {
		case <-l.C:
			if c.onlineCnt > 0 {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
