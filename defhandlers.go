package spotlib

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/emitter"
	"github.com/KarpelesLab/spotproto"
)

// setDefaultHandlers initializes default handlers for standard endpoints:
// - ping: Echo service for testing connectivity
// - version: Reports library and runtime version
// - finger: Returns the client's signed identity for verification
// - check_update: Triggers update check events
// - idcard_update: Handles ID card update notifications from the server
func (c *Client) setDefaultHandlers() {
	c.SetHandler("ping", func(msg *spotproto.Message) ([]byte, error) {
		if len(msg.Body) > 128 {
			return msg.Body[:128], nil
		}
		return msg.Body, nil
	})
	c.SetHandler("version", func(msg *spotproto.Message) ([]byte, error) {
		res := fmt.Sprintf("spotlib, %s", runtime.Version())
		return []byte(res), nil
	})
	c.SetHandler("finger", func(msg *spotproto.Message) ([]byte, error) {
		return c.idBin, nil
	})
	c.SetHandler("check_update", func(msg *spotproto.Message) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		emitter.Global.Emit(ctx, "check_update")
		return nil, nil
	})
	c.SetHandler("idcard_update", func(msg *spotproto.Message) ([]byte, error) {
		// Process ID card update notifications
		if len(msg.Body) == 0 {
			return nil, fmt.Errorf("empty ID card data received")
		}

		// Parse the ID card from binary data
		idc := &cryptutil.IDCard{}
		err := idc.UnmarshalBinary(msg.Body)
		if err != nil {
			c.logf("failed to parse ID card update: %s", err)
			return nil, fmt.Errorf("invalid ID card format: %w", err)
		}

		// Get hash of the ID card
		idHash := cryptutil.Hash(idc.Self, sha256.New)

		// Update the ID card in the cache and check if it was an update or new entry
		c.setIDCardCache(idHash, idc)

		c.logf("updated ID card in cache: k.%s", base64.RawURLEncoding.EncodeToString(idHash))

		// No response needed for this notification
		return nil, nil
	})
}
