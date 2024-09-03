package spotlib

import (
	"context"
	"fmt"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/spotproto"
)

type MessageHandler func(msg *spotproto.Message) ([]byte, error)

func (c *Client) SetHandler(endpoint string, handler MessageHandler) {
	c.msghdlrLk.Lock()
	defer c.msghdlrLk.Unlock()

	if handler == nil {
		delete(c.msghdlr, endpoint)
	} else {
		c.msghdlr[endpoint] = handler
	}
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
		Sender:    "/noreply",
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