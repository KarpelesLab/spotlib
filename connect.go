package spotlib

import (
	"context"

	"github.com/KarpelesLab/rest"
)

type conn struct {
	host string
	c    *Client
}

func (c *Client) getConn(host string) *conn {
	c.connsLk.Lock()
	defer c.connsLk.Unlock()

	if v, ok := c.conns[host]; ok {
		return v
	}
	return nil
}

func (c *Client) regConn(co *conn) {
	c.connsLk.Lock()
	defer c.connsLk.Unlock()

	c.conns[co.host] = co
}

func (c *Client) unregConn(co *conn) bool {
	c.connsLk.Lock()
	defer c.connsLk.Unlock()

	if v, ok := c.conns[co.host]; ok && v == co {
		delete(c.conns, co.host)
		return true
	}
	return false
}

func getHosts(ctx context.Context) ([]string, error) {
	// call Spot:connect API to fetch hosts we can connect to
	var res *struct {
		Hosts []string `json:"hosts"`
	}
	err := rest.Apply(ctx, "Spot:connect", "GET", nil, &res)
	if err != nil {
		return nil, err
	}
	return res.Hosts, nil
}

func (c *Client) runConnect() error {
	hosts, err := getHosts(context.Background())
	if err != nil {
		return err
	}
	if len(hosts) > 10 {
		hosts = hosts[:10]
	}

	for _, h := range hosts {
		if c.getConn(h) == nil {
			co := &conn{
				host: h,
				c:    c,
			}
			c.regConn(co)
			go co.run()
		}
	}

	return nil
}

func (co *conn) run() {
	defer co.c.unregConn(co)
}
