package spotlib

import (
	"fmt"
	"runtime"

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
}
