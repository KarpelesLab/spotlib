package spotlib

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/spotproto"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type MessageHandler func(msg *spotproto.Message) ([]byte, error)

// Client holds information about a client, including its connections to the spot servers
type Client struct {
	s         *ecdsa.PrivateKey // main signer for connection/etc
	id        *cryptutil.IDCard
	idBin     []byte // signed id
	idLk      sync.Mutex
	kc        *cryptutil.Keychain
	mWrQ      chan *spotproto.Message // message write queue
	conns     map[string]*conn
	connsLk   sync.Mutex
	connCnt   uint32
	onlineCnt uint32 // number of online connections
	inQ       map[string]chan any
	inQLk     sync.Mutex
	msghdlr   map[string]MessageHandler
	msghdlrLk sync.RWMutex
}

// New starts a new Client and establishes connection to the Spot system. If any key is passed,
// the first key will be used as the main signing key.
func New(params ...any) (*Client, error) {
	c := &Client{
		kc:      cryptutil.NewKeychain(),
		conns:   make(map[string]*conn),
		mWrQ:    make(chan *spotproto.Message, 4),
		inQ:     make(map[string]chan any),
		msghdlr: make(map[string]MessageHandler),
	}

	// generate a new ecdsa private key
	var err error
	c.s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	meta := make(map[string]string)

	for _, p := range params {
		switch v := p.(type) {
		case *cryptutil.Keychain:
			c.kc.AddKey(v)
		case cryptutil.PrivateKey:
			c.kc.AddKey(v)
		case map[string]string:
			for k, s := range v {
				meta[k] = s
			}
		}
	}

	c.kc.AddKey(c.s)

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

// IDCard returns our own IDCard
func (c *Client) IDCard() *cryptutil.IDCard {
	return c.id
}

// TargetId returns the local client ID that can be used to transmit messages
func (c *Client) TargetId() string {
	return "k:" + base64.RawURLEncoding.EncodeToString(cryptutil.Hash(c.id.Self, sha256.New))
}

// ConnectionCount returns the number of spot server connections, and the number of
// said connections which are online (ie. past the handshake step).
func (c *Client) ConnectionCount() (uint32, uint32) {
	return atomic.LoadUint32(&c.connCnt), atomic.LoadUint32(&c.onlineCnt)
}

// Query sends a non-encrypted request & waits for the response
func (c *Client) Query(ctx context.Context, target string, body []byte) ([]byte, error) {
	id := uuid.New()
	ch := c.makeInQ(id.String())
	defer c.takeInQ(id.String())

	msg := &spotproto.Message{
		MessageID: id,
		Flags:     spotproto.MsgFlagNotBottle,
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
		case []byte:
			return obj, nil
		case *spotproto.Message:
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

// GetIDCardBin returns the binary ID card for the given hash
func (c *Client) GetIDCardBin(ctx context.Context, h []byte) ([]byte, error) {
	// TODO add local cache
	return c.Query(ctx, "@/find", h)
}

// GetIDCard returns the ID card for the given hash
func (c *Client) GetIDCard(ctx context.Context, h []byte) (*cryptutil.IDCard, error) {
	buf, err := c.GetIDCardBin(ctx, h)
	if err != nil {
		return nil, err
	}
	idc := &cryptutil.IDCard{}
	err = idc.UnmarshalBinary(buf)
	if err != nil {
		return nil, err
	}
	return idc, nil
}

// GetIDCardForRecipient returns the ID Card of a given recipient, if any
func (c *Client) GetIDCardForRecipient(ctx context.Context, rcv string) (*cryptutil.IDCard, error) {
	// rcv has the format: k:<base64url hash>/<endpoint>
	if pos := strings.IndexByte(rcv, '/'); pos > 0 {
		rcv = rcv[:pos]
	}
	rcvA := strings.Split(rcv, ":")
	if len(rcvA) == 1 || rcvA[0] != "k" {
		return nil, errors.New("invalid recipient")
	}
	h, err := base64.RawURLEncoding.DecodeString(rcvA[len(rcvA)-1])
	if err != nil {
		return nil, err
	}
	return c.GetIDCard(ctx, h)
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
	rid, err := c.GetIDCardForRecipient(ctx, target)
	if err != nil {
		return fmt.Errorf("failed to find recipient: %w", err)
	}

	body, err := c.prepareMessage(rid, payload)
	if err != nil {
		return fmt.Errorf("failed to prepare message: %w", err)
	}

	id := uuid.New()

	msg := &spotproto.Message{
		MessageID: id,
		Flags:     0,
		Sender:    "/" + id.String(),
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

func (c *Client) getHandler(endpoint string) MessageHandler {
	c.msghdlrLk.RLock()
	defer c.msghdlrLk.RUnlock()

	if v, ok := c.msghdlr[endpoint]; ok {
		return v
	}
	return nil
}

func (c *Client) runHandler(msg *spotproto.Message, h MessageHandler) {
	var rid *cryptutil.IDCard
	var err error

	if msg.Flags&spotproto.MsgFlagNotBottle == 0 {
		rid, err = c.GetIDCardForRecipient(context.TODO(), msg.Sender)
		if err != nil {
			c.logf("cannot send encrypted response: %s", err)
			return
		}
		// need to decrypt this bottle
		msg.Body, err = c.decodeMessage(rid, msg.Body)
		if err != nil {
			c.logf("failed to decode incoming message: %s", err)
			return
		}
	}

	// we're running in a goroutine
	// use safeRunHandler (which has a recover()) so a panic would not kill the whole process
	res, err := c.safeRunHandler(msg, h)

	if msg.Flags&spotproto.MsgFlagResponse == spotproto.MsgFlagResponse {
		// do not generate a response to a response
		return
	}

	resFlags := uint64(spotproto.MsgFlagResponse)
	if err != nil {
		res = []byte(err.Error())
		resFlags |= spotproto.MsgFlagError
	}

	if res == nil {
		// no response
		return
	}

	if msg.Flags&spotproto.MsgFlagNotBottle == 0 {
		// we got a bottle, need to respond with a bottle
		res, err = c.prepareMessage(rid, res)
		if err != nil {
			c.logf("failed to prepare response: %s", err)
			return
		}
	}

	respMsg := &spotproto.Message{
		MessageID: msg.MessageID,
		Flags:     resFlags,
		Recipient: msg.Sender,
		Sender:    msg.Recipient,
		Body:      res,
	}

	c.mWrQ <- respMsg
}

func (c *Client) safeRunHandler(msg *spotproto.Message, h MessageHandler) (buf []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			switch v := e.(type) {
			case error:
				err = fmt.Errorf("panic in handler: %w", v)
			default:
				err = fmt.Errorf("panic in handler: %v", e)
			}
		}
	}()

	buf, err = h(msg)
	return
}
