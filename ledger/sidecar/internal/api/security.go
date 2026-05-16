package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultRateLimitPerMinute = 600
	defaultRateLimitBurst     = 120
)

type rateLimiter struct {
	mu       sync.Mutex
	rate     float64
	burst    float64
	buckets  map[string]*rateBucket
	lastTrim time.Time
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute, burst int) *rateLimiter {
	if perMinute <= 0 {
		perMinute = defaultRateLimitPerMinute
	}
	if burst <= 0 {
		burst = defaultRateLimitBurst
	}
	return &rateLimiter{
		rate:     float64(perMinute) / 60.0,
		burst:    float64(burst),
		buckets:  make(map[string]*rateBucket),
		lastTrim: time.Now(),
	}
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastTrim) > 5*time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastTrim = now
	}

	b := l.buckets[key]
	if b == nil {
		l.buckets[key] = &rateBucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", strings.Join([]string{
			"default-src 'self'",
			"base-uri 'self'",
			"object-src 'none'",
			"frame-ancestors 'none'",
			"form-action 'self'",
			"script-src 'self'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"connect-src 'self'",
		}, "; "))
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimitMiddleware() func(http.Handler) http.Handler {
	if s.limiter == nil {
		s.limiter = newRateLimiter(s.RateLimitPerMinute, s.RateLimitBurst)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rateLimitExempt(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			key := clientIP(r)
			if !s.limiter.allow(key) {
				w.Header().Set("Retry-After", "60")
				writeErr(w, http.StatusTooManyRequests, errors.New("rate limit exceeded"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func rateLimitExempt(path string) bool {
	return path == "/api/v1/health" ||
		strings.HasPrefix(path, "/admin/static/") ||
		strings.HasPrefix(path, "/explorer/static/")
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
