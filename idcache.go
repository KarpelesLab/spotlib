package spotlib

import (
	"time"

	"github.com/KarpelesLab/cryptutil"
)

type idCacheEntry struct {
	id *cryptutil.IDCard
	t  time.Time
}

func (c *Client) getIDCardFromCache(h []byte) *cryptutil.IDCard {
	c.idCacheLk.RLock()
	defer c.idCacheLk.RUnlock()

	//  handle expiration in cache

	v, ok := c.idCache[string(h)]
	if !ok {
		return nil
	}
	return v.id
}

func (c *Client) setIDCardCache(h []byte, obj *cryptutil.IDCard) {
	c.idCacheLk.Lock()
	defer c.idCacheLk.Unlock()

	if len(c.idCache) > 1024 {
		// cache overfill protection
		clear(c.idCache)
	}

	e := &idCacheEntry{
		id: obj,
		t:  time.Now(),
	}

	c.idCache[string(h)] = e
}

func (c *Client) needKeyRefresh() {
	c.idCacheLk.Lock()
	defer c.idCacheLk.Unlock()

	// for now we only clear the cache, actually we should send a signal on a channel that will trigger a waiting
	// thread to send the list of cached ids (id+modified timestamp in secs) for the server to respond if the ID
	// is known and up to date, known and outdated (flush from cache) ou not known (flush from cache).
	//
	// This would help ensure that IDs are always up to date
	clear(c.idCache)
}
