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

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/emitter"
	"github.com/KarpelesLab/spotproto"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// Client holds information about a client, including its connections to the spot servers
type Client struct {
	s           crypto.Signer // main signer for connection/etc
	Events      *emitter.Hub
	id          *cryptutil.IDCard
	idBin       []byte // signed id
	idLk        sync.Mutex
	kc          *cryptutil.Keychain
	mWrQ        chan *spotproto.Message // message write queue
	conns       map[string]*conn
	connsLk     sync.Mutex
	minConn     uint32
	connCnt     uint32
	onlineCnt   uint32 // number of online connections
	onlineCntLk sync.RWMutex
	onlineCond  *sync.Cond
	inQ         map[string]chan any
	inQLk       sync.Mutex
	msghdlr     map[string]MessageHandler
	msghdlrLk   sync.RWMutex
	idCache     map[string]*cryptutil.IDCard
	idCacheLk   sync.RWMutex
	alive       chan struct{}
	closed      uint32
}

// New starts a new Client and establishes connection to the Spot system. If any key is passed,
// the first key will be used as the main signing key.
func New(params ...any) (*Client, error) {
	c := &Client{
		Events:  emitter.New(),
		kc:      cryptutil.NewKeychain(),
		minConn: 1,
		conns:   make(map[string]*conn),
		mWrQ:    make(chan *spotproto.Message, 4),
		inQ:     make(map[string]chan any),
		msghdlr: make(map[string]MessageHandler),
		idCache: make(map[string]*cryptutil.IDCard),
		alive:   make(chan struct{}),
	}
	c.onlineCond = sync.NewCond(c.onlineCntLk.RLocker())

	// generate a new ecdsa private key
	var err error
	meta := make(map[string]string)

	for _, p := range params {
		switch v := p.(type) {
		case *cryptutil.Keychain:
			c.kc.AddKey(v)
		case cryptutil.PrivateKey:
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

	if c.s == nil {
		c.s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		c.kc.AddKey(c.s)
	}

	// this shouldn't fail at this point since the keys added successfully to the keychain, but check anyway just in case
	pub := cryptutil.PublicKey(c.kc.FirstSigner())
	if pub == nil {
		return nil, fmt.Errorf("bad key type %T", c.kc.FirstSigner())
	}

	// generate a client ID
	c.id, err = cryptutil.NewIDCard(pub)
	if err != nil {
		return nil, err
	}
	c.id.Meta = meta
	c.id.AddKeychain(c.kc)

	// sign the ID
	c.idBin, err = c.id.Sign(rand.Reader, c.kc.FirstSigner())
	if err != nil {
		return nil, err
	}

	// start the connection thread
	go c.mainThread()

	return c, nil
}

func (c *Client) Close() error {
	if atomic.AddUint32(&c.closed, 1) == 1 {
		close(c.alive)
		c.alive = nil
	}
	return nil
}

// IDCard returns our own IDCard
func (c *Client) IDCard() *cryptutil.IDCard {
	return c.id
}

// TargetId returns the local client ID that can be used to transmit messages
func (c *Client) TargetId() string {
	return "k." + base64.RawURLEncoding.EncodeToString(cryptutil.Hash(c.id.Self, sha256.New))
}

// ConnectionCount returns the number of spot server connections, and the number of
// said connections which are online (ie. past the handshake step).
func (c *Client) ConnectionCount() (uint32, uint32) {
	return atomic.LoadUint32(&c.connCnt), atomic.LoadUint32(&c.onlineCnt)
}

// Query sends a request & waits for the response. If the target is a key (starts with k:) the
// message will be encrypted & signed so only the recipient can open it.
func (c *Client) Query(ctx context.Context, target string, body []byte) ([]byte, error) {
	if len(target) == 0 {
		return nil, errors.New("invalid target")
	}

	var msgFlags uint64
	var rid *cryptutil.IDCard
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
		msgFlags |= spotproto.MsgFlagNotBottle
	}

	id := uuid.New()
	ch := c.makeInQ(id.String())
	defer c.takeInQ(id.String())

	msg := &spotproto.Message{
		MessageID: id,
		Flags:     msgFlags,
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
			if rid != nil {
				// decrypt message
				obj.Body, err = c.decodeMessage(rid, obj.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to decode response: %w", err)
				}
			}
			return obj.Body, nil
		default:
			return nil, fmt.Errorf("invalid message response type %T", v)
		}
	}
}

// QueryTimeout calls Query with the specified timeout
func (c *Client) QueryTimeout(timeout time.Duration, target string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.Query(ctx, target, body)
}

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

// GetIDCardBin returns the binary ID card for the given hash
func (c *Client) GetIDCardBin(ctx context.Context, h []byte) ([]byte, error) {
	// TODO add local cache
	return c.Query(ctx, "@/find", h)
}

func (c *Client) getIDCardFromCache(h []byte) *cryptutil.IDCard {
	c.idCacheLk.RLock()
	defer c.idCacheLk.RUnlock()

	// TODO handle expiration in cache

	if v, ok := c.idCache[string(h)]; ok {
		return v
	}
	return nil
}

func (c *Client) setIDCardCache(h []byte, obj *cryptutil.IDCard) {
	c.idCacheLk.Lock()
	defer c.idCacheLk.Unlock()

	if len(c.idCache) > 1024 {
		// cache overfill protection
		clear(c.idCache)
	}

	c.idCache[string(h)] = obj
}

// GetIDCard returns the ID card for the given hash
func (c *Client) GetIDCard(ctx context.Context, h []byte) (*cryptutil.IDCard, error) {
	if obj := c.getIDCardFromCache(h); obj != nil {
		return obj, nil
	}
	buf, err := c.GetIDCardBin(ctx, h)
	if err != nil {
		return nil, err
	}
	idc := &cryptutil.IDCard{}
	err = idc.UnmarshalBinary(buf)
	if err != nil {
		return nil, err
	}
	c.setIDCardCache(h, idc)
	return idc, nil
}

// GetIDCardForRecipient returns the ID Card of a given recipient, if any
func (c *Client) GetIDCardForRecipient(ctx context.Context, rcv string) (*cryptutil.IDCard, error) {
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

func (c *Client) prepareMessage(rid *cryptutil.IDCard, payload []byte) ([]byte, error) {
	bottle := cryptutil.NewBottle(payload)
	err := bottle.Encrypt(rand.Reader, rid)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}
	bottle.BottleUp()
	err = bottle.Sign(rand.Reader, c.s)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	body, err := cbor.Marshal(bottle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bottle: %w", err)
	}

	return body, nil
}

func (c *Client) decodeMessage(rid *cryptutil.IDCard, payload []byte) ([]byte, error) {
	// need to decrypt this bottle
	bottle := cryptutil.AsCborBottle(payload)
	buf, info, err := cryptutil.MustOpener(c.kc).Open(bottle)
	if err != nil {
		return nil, fmt.Errorf("failed to open bottle: %w", err)
	}
	if info.Decryption == 0 {
		return nil, errors.New("incoming message is not encrypted")
	}
	if !info.SignedBy(rid) {
		return nil, errors.New("incoming message is not signed by sender")
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
			if cnt < c.minConn {
				// require at least 2 active connections
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
	idBin, err := c.id.Sign(rand.Reader, c.kc.FirstSigner())
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

func (c *Client) onlineIncr() {
	c.onlineCntLk.Lock()
	defer c.onlineCntLk.Unlock()
	c.onlineCnt += 1
	if c.onlineCnt == 1 {
		// we went from 0 to 1, emit event
		go c.Events.EmitTimeout(15*time.Second, "status", 1)
		c.onlineCond.Broadcast()
	}
}

func (c *Client) onlineDecr() {
	c.onlineCntLk.Lock()
	defer c.onlineCntLk.Unlock()

	c.onlineCnt -= 1
	if c.onlineCnt == 0 {
		// we went offline, emit event
		go c.Events.EmitTimeout(15*time.Second, "status", 0)
	}
}

func (c *Client) WaitOnline() {
	c.onlineCntLk.RLock()
	defer c.onlineCntLk.RUnlock()

	for {
		if c.onlineCnt > 0 {
			return
		}
		c.onlineCond.Wait()
	}
}
