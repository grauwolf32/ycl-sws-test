package lab

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
)

//go:embed web/index.html web/assets/*
var webFiles embed.FS

type contextKey string

const requestIDKey contextKey = "request-id"

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)

// Server is the HTTP test application.
type Server struct {
	cfg     Config
	logger  *slog.Logger
	stats   *requestStats
	mux     *http.ServeMux
	index   *template.Template
	assets  http.Handler
	started time.Time
}

// New initializes a server without opening a network listener.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	index, err := template.ParseFS(webFiles, "web/index.html")
	if err != nil {
		return nil, fmt.Errorf("parse index template: %w", err)
	}
	assetFS, err := fs.Sub(webFiles, "web/assets")
	if err != nil {
		return nil, fmt.Errorf("open embedded assets: %w", err)
	}

	s := &Server{
		cfg:     cfg,
		logger:  logger,
		stats:   newRequestStats(),
		mux:     http.NewServeMux(),
		index:   index,
		assets:  http.StripPrefix("/assets/", http.FileServer(http.FS(assetFS))),
		started: time.Now().UTC(),
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("GET /favicon.svg", s.handleFavicon)
	s.mux.HandleFunc("GET /assets/{name...}", s.handleAsset)

	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleHealth)
	s.mux.HandleFunc("GET /api/inspect", s.handleInspect)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/echo", s.handleEcho)
	s.mux.HandleFunc("POST /api/echo", s.handleEcho)

	s.mux.HandleFunc("POST /api/waf/form", s.handleWAFForm)
	s.mux.HandleFunc("POST /api/waf/json", s.handleWAFJSON)
	s.mux.HandleFunc("POST /api/waf/upload", s.handleWAFUpload)
	s.mux.HandleFunc("GET /api/waf/path/{value...}", s.handleWAFPath)

	s.mux.HandleFunc("GET /api/catalog", s.handleCatalog)
	s.mux.HandleFunc("GET /api/catalog/{id}", s.handleCatalogItem)
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/antibot/beacon", s.handleBeacon)
	s.mux.HandleFunc("GET /api/slow", s.handleSlow)
	s.mux.HandleFunc("GET /api/status/{code}", s.handleStatus)
	s.mux.HandleFunc("GET /protected/admin", s.handleProtected)
}

// Handler returns the fully instrumented HTTP handler.
func (s *Server) Handler() http.Handler {
	var handler http.Handler = s.mux
	handler = s.limitRequestBody(handler)
	handler = s.recoverPanics(handler)
	handler = s.observeRequests(handler)
	handler = s.securityHeaders(handler)
	handler = s.assignRequestID(handler)
	return handler
}

func (s *Server) assignRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if !validRequestID.MatchString(requestID) {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, requestID)))
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Lab-Response", "origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic recovered",
					"request_id", requestIDFromContext(r.Context()),
					"panic", recovered,
					"stack", string(debug.Stack()),
				)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) observeRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isALBHTTPHealthCheck(r) {
			next.ServeHTTP(w, r)
			return
		}

		started := time.Now()
		recorder := &responseRecorder{ResponseWriter: w}
		s.stats.begin()

		defer func() {
			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}
			s.stats.finish(r, status)
			s.logger.Info("request",
				"request_id", requestIDFromContext(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"route", r.Pattern,
				"status", status,
				"bytes", recorder.bytes,
				"duration_ms", time.Since(started).Milliseconds(),
				"client_ip", s.clientIP(r),
				"user_agent", r.UserAgent(),
			)
		}()

		next.ServeHTTP(recorder, r)
	})
}

func isALBHTTPHealthCheck(r *http.Request) bool {
	if r.UserAgent() != "Envoy/HC" || strings.TrimSpace(r.Header.Get("X-Forwarded-For")) != "" {
		return false
	}
	return r.URL.Path == "/" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz"
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(data)
	r.bytes += n
	return n, err
}

func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (s *Server) clientIP(r *http.Request) string {
	remoteIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteIP = host
	}
	if !s.cfg.TrustProxyHeaders {
		return remoteIP
	}

	for _, candidate := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		candidate = strings.TrimSpace(candidate)
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	if candidate := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(candidate) != nil {
		return candidate
	}
	return remoteIP
}

func newRequestID() string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("lab-%d", time.Now().UnixNano())
	}
	return "lab-" + hex.EncodeToString(buffer)
}

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": message,
	})
}

func writeReadError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid request body")
}
