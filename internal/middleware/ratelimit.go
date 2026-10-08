package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type ipEntry struct {
	count   int
	resetAt time.Time
}

// maxClients caps the rate-limiter map to prevent memory exhaustion if an
// attacker sends requests from a large number of source IPs.  When the cap
// is reached, all expired entries are purged inline before processing the
// new request.
const maxClients = 50_000

// RateLimit returns middleware that limits requests per IP address.
// maxRequests per window duration; excess requests receive 429.
func RateLimit(maxRequests int, window time.Duration) gin.HandlerFunc {
	var mu sync.Mutex
	clients := make(map[string]*ipEntry)

	// Background cleanup of expired entries every window period.
	go func() {
		for {
			time.Sleep(window)
			mu.Lock()
			now := time.Now()
			for ip, entry := range clients {
				if now.After(entry.resetAt) {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()

		mu.Lock()

		// Evict expired entries if the map has grown too large.
		if len(clients) >= maxClients {
			for k, e := range clients {
				if now.After(e.resetAt) {
					delete(clients, k)
				}
			}
		}

		entry, exists := clients[ip]
		if !exists || now.After(entry.resetAt) {
			clients[ip] = &ipEntry{count: 1, resetAt: now.Add(window)}
			mu.Unlock()
			c.Next()
			return
		}
		entry.count++
		if entry.count > maxRequests {
			mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many requests, try again later",
			})
			return
		}
		mu.Unlock()
		c.Next()
	}
}

// MaxInFlight lets at most n requests run the rest of the chain at once;
// further requests get 429 instead of queueing. It bounds the memory of
// expensive handlers such as the bundle import.
func MaxInFlight(n int) gin.HandlerFunc {
	slots := make(chan struct{}, n)
	return func(c *gin.Context) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			c.Next()
		default:
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "server busy, try again shortly",
			})
		}
	}
}
