package spotlib

import (
	"time"

	"github.com/BottleFmt/gobottle"
)

// idCacheEntry represents a cached ID card with a timestamp for expiration handling
type idCacheEntry struct {
	id *gobottle.IDCard // The cached identity card
	t  time.Time        // Time when the entry was cached
}

// getIDCardFromCache retrieves an ID card from the cache if it exists
// Returns nil if the hash is not found in the cache
func (c *Client) getIDCardFromCache(h []byte) *gobottle.IDCard {
	c.idCacheLk.RLock()
	defer c.idCacheLk.RUnlock()

	//  handle expiration in cache

	v, ok := c.idCache[string(h)]
	if !ok {
		return nil
	}
	return v.id
}

// setIDCardCache adds or updates an ID card in the cache
// Includes protection against cache overfill by clearing the cache if it grows too large
// Returns true if this was a cache update (not a new entry)
func (c *Client) setIDCardCache(h []byte, obj *gobottle.IDCard) bool {
	c.idCacheLk.Lock()
	defer c.idCacheLk.Unlock()

	if len(c.idCache) > 1024 {
		// cache overfill protection
		clear(c.idCache)
	}

	// Check if this is an update to an existing entry
	isUpdate := false
	key := string(h)
	if _, exists := c.idCache[key]; exists {
		isUpdate = true
	}

	e := &idCacheEntry{
		id: obj,
		t:  time.Now(),
	}

	c.idCache[key] = e
	return isUpdate
}

// needKeyRefresh clears the ID cache when signature verification fails
// This triggers fetching fresh ID cards when needed
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
