package spotlib

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/KarpelesLab/emitter"
	"github.com/KarpelesLab/spotproto"
)

// setDefaultHandlers initializes default handlers
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
}
