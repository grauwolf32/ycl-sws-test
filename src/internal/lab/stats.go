package lab

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type requestStats struct {
	startedAt time.Time
	total     atomic.Uint64
	active    atomic.Int64

	mu       sync.RWMutex
	byMethod map[string]uint64
	byRoute  map[string]uint64
	byStatus map[string]uint64
	byClient map[string]uint64
}

type statsSnapshot struct {
	StartedAt string            `json:"started_at"`
	UptimeSec int64             `json:"uptime_seconds"`
	Total     uint64            `json:"requests_received"`
	Active    int64             `json:"requests_active"`
	ByMethod  map[string]uint64 `json:"by_method"`
	ByRoute   map[string]uint64 `json:"by_route"`
	ByStatus  map[string]uint64 `json:"by_status"`
	ByClient  map[string]uint64 `json:"by_client_type"`
	Note      string            `json:"note"`
}

func newRequestStats() *requestStats {
	return &requestStats{
		startedAt: time.Now().UTC(),
		byMethod:  make(map[string]uint64),
		byRoute:   make(map[string]uint64),
		byStatus:  make(map[string]uint64),
		byClient:  make(map[string]uint64),
	}
}

func (s *requestStats) begin() {
	s.active.Add(1)
}

func (s *requestStats) finish(r *http.Request, status int) {
	s.active.Add(-1)
	s.total.Add(1)

	route := r.Pattern
	if route == "" {
		route = "unmatched"
	}

	s.mu.Lock()
	s.byMethod[r.Method]++
	s.byRoute[route]++
	s.byStatus[statusClass(status)]++
	s.byClient[classifyUserAgent(r.UserAgent())]++
	s.mu.Unlock()
}

func (s *requestStats) snapshot() statsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return statsSnapshot{
		StartedAt: s.startedAt.Format(time.RFC3339),
		UptimeSec: int64(time.Since(s.startedAt).Seconds()),
		Total:     s.total.Load(),
		Active:    s.active.Load(),
		ByMethod:  cloneCounts(s.byMethod),
		ByRoute:   cloneCounts(s.byRoute),
		ByStatus:  cloneCounts(s.byStatus),
		ByClient:  cloneCounts(s.byClient),
		Note:      "Requests blocked by SWS do not reach this counter.",
	}
}

func cloneCounts(source map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func statusClass(status int) string {
	if status < 100 {
		status = http.StatusOK
	}
	return string(rune('0'+status/100)) + "xx"
}

func classifyUserAgent(userAgent string) string {
	value := strings.ToLower(strings.TrimSpace(userAgent))
	switch {
	case value == "":
		return "empty-user-agent"
	case strings.Contains(value, "headless"),
		strings.Contains(value, "selenium"),
		strings.Contains(value, "playwright"),
		strings.Contains(value, "puppeteer"):
		return "headless-browser"
	case strings.Contains(value, "curl"),
		strings.Contains(value, "wget"),
		strings.Contains(value, "python"),
		strings.Contains(value, "go-http-client"),
		strings.Contains(value, "httpie"):
		return "http-client"
	case strings.Contains(value, "bot"),
		strings.Contains(value, "crawler"),
		strings.Contains(value, "spider"):
		return "declared-bot"
	case strings.Contains(value, "mozilla/"):
		return "browser-like"
	default:
		return "other"
	}
}
