package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type indexData struct {
	AppName           string
	MaxBodyBytes      int64
	MaxDelayMS        int64
	TrustProxyHeaders bool
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.index.ExecuteTemplate(w, "index.html", indexData{
		AppName:           s.cfg.AppName,
		MaxBodyBytes:      s.cfg.MaxBodyBytes,
		MaxDelayMS:        s.cfg.MaxDelay.Milliseconds(),
		TrustProxyHeaders: s.cfg.TrustProxyHeaders,
	}); err != nil {
		s.logger.Error("render index", "error", err)
	}
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	s.assets.ServeHTTP(w, r)
}

func (s *Server) handleFavicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.WriteString(w, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#111827"/><path d="M17 18h30L35 47h-8z" fill="#ffcc00"/><circle cx="32" cy="29" r="5" fill="#111827"/></svg>`)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"service":        "sws-lab",
		"started_at":     s.started.Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(s.started).Seconds()),
	})
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	selectedHeaders := make(map[string][]string)
	for _, name := range []string{
		"Accept",
		"Accept-Encoding",
		"Content-Type",
		"Forwarded",
		"User-Agent",
		"Via",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"X-Forwarded-Proto",
		"X-Real-IP",
		"X-Request-ID",
	} {
		if values := r.Header.Values(name); len(values) > 0 {
			selectedHeaders[name] = values
		}
	}

	query := make(map[string][]string, len(r.URL.Query()))
	for name, values := range r.URL.Query() {
		query[name] = append([]string(nil), values...)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                    true,
		"method":                r.Method,
		"path":                  r.URL.Path,
		"query":                 query,
		"host":                  r.Host,
		"protocol":              r.Proto,
		"tls_at_origin":         r.TLS != nil,
		"remote_addr":           r.RemoteAddr,
		"effective_client_ip":   s.clientIP(r),
		"proxy_headers_trusted": s.cfg.TrustProxyHeaders,
		"selected_headers":      selectedHeaders,
		"request_id":            requestIDFromContext(r.Context()),
		"received_at":           time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.stats.snapshot()
	// The metrics request is active while its own snapshot is taken. Hide that
	// implementation detail so an otherwise idle origin reports zero.
	if snapshot.Active > 0 {
		snapshot.Active--
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	var value any
	if r.Method == http.MethodGet {
		value = r.URL.Query().Get("value")
	} else {
		mediaType := requestMediaType(r)
		switch mediaType {
		case "application/json":
			if err := decodeSingleJSON(r.Body, &value); err != nil {
				writeReadError(w, err)
				return
			}
		case "application/x-www-form-urlencoded":
			if err := r.ParseForm(); err != nil {
				writeReadError(w, err)
				return
			}
			value = copyValues(r.PostForm, 50, 20)
		default:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				writeReadError(w, err)
				return
			}
			value = string(body)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"value":      value,
		"executed":   false,
		"stored":     false,
		"request_id": requestIDFromContext(r.Context()),
	})
}

func (s *Server) handleWAFForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"payload":    copyValues(r.PostForm, 50, 20),
		"executed":   false,
		"stored":     false,
		"message":    "Payload reached the origin and was handled as inert text.",
		"request_id": requestIDFromContext(r.Context()),
	})
}

func (s *Server) handleWAFJSON(w http.ResponseWriter, r *http.Request) {
	if requestMediaType(r) != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	var payload any
	if err := decodeSingleJSON(r.Body, &payload); err != nil {
		writeReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"payload":    payload,
		"executed":   false,
		"stored":     false,
		"message":    "JSON reached the origin and was decoded without interpretation.",
		"request_id": requestIDFromContext(r.Context()),
	})
}

type uploadedPart struct {
	FieldName string `json:"field_name"`
	FileName  string `json:"file_name,omitempty"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

func (s *Server) handleWAFUpload(w http.ResponseWriter, r *http.Request) {
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be multipart/form-data")
		return
	}

	parts := make([]uploadedPart, 0, 4)
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			writeReadError(w, nextErr)
			return
		}
		if len(parts) >= 32 {
			_ = part.Close()
			writeError(w, http.StatusBadRequest, "too many multipart fields")
			return
		}

		hash := sha256.New()
		size, copyErr := io.Copy(hash, part)
		closeErr := part.Close()
		if copyErr != nil {
			writeReadError(w, copyErr)
			return
		}
		if closeErr != nil {
			writeReadError(w, closeErr)
			return
		}
		parts = append(parts, uploadedPart{
			FieldName: part.FormName(),
			FileName:  part.FileName(),
			Size:      size,
			SHA256:    hex.EncodeToString(hash.Sum(nil)),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"parts":      parts,
		"executed":   false,
		"stored":     false,
		"message":    "Parts were hashed in memory and discarded.",
		"request_id": requestIDFromContext(r.Context()),
	})
}

func (s *Server) handleWAFPath(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"path_value": r.PathValue("value"),
		"raw_path":   r.URL.RawPath,
		"executed":   false,
		"request_id": requestIDFromContext(r.Context()),
	})
}

type catalogItem struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Price    int    `json:"price"`
}

var catalog = []catalogItem{
	{ID: 1, Name: "Amber keyboard", Category: "devices", Price: 7900},
	{ID: 2, Name: "Graphite mouse", Category: "devices", Price: 3600},
	{ID: 3, Name: "Cloud notebook", Category: "stationery", Price: 490},
	{ID: 4, Name: "Signal mug", Category: "merch", Price: 1200},
	{ID: 5, Name: "Edge hoodie", Category: "merch", Price: 5900},
	{ID: 6, Name: "Shield sticker pack", Category: "merch", Price: 350},
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	page := boundedInt(r.URL.Query().Get("page"), 1, 1, 100)
	limit := boundedInt(r.URL.Query().Get("limit"), 3, 1, 20)
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	filtered := make([]catalogItem, 0, len(catalog))
	for _, item := range catalog {
		if query == "" || strings.Contains(strings.ToLower(item.Name+" "+item.Category), query) {
			filtered = append(filtered, item)
		}
	}

	start := (page - 1) * limit
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"items":      filtered[start:end],
		"page":       page,
		"limit":      limit,
		"total":      len(filtered),
		"request_id": requestIDFromContext(r.Context()),
	})
}

func (s *Server) handleCatalogItem(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "catalog id must be a number")
		return
	}
	for _, item := range catalog {
		if item.ID == id {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":         true,
				"item":       item,
				"request_id": requestIDFromContext(r.Context()),
			})
			return
		}
	}
	writeError(w, http.StatusNotFound, "catalog item not found")
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var credentials loginRequest
	if requestMediaType(r) == "application/json" {
		if err := decodeSingleJSON(r.Body, &credentials); err != nil {
			writeReadError(w, err)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writeReadError(w, err)
			return
		}
		credentials.Username = r.PostForm.Get("username")
		credentials.Password = r.PostForm.Get("password")
	}

	if credentials.Username != "demo" || credentials.Password != "demo" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":                false,
			"authenticated":     false,
			"username_received": credentials.Username,
			"password_received": credentials.Password != "",
			"message":           "This is a deterministic lab login; use demo/demo for a baseline request.",
		})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "sws_lab_session",
		Value:    newRequestID(),
		Path:     "/",
		MaxAge:   900,
		HttpOnly: true,
		Secure:   s.isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"authenticated": true,
		"username":      "demo",
		"message":       "A short-lived, non-privileged lab cookie was issued.",
	})
}

func (s *Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	var event map[string]any
	if err := decodeSingleJSON(r.Body, &event); err != nil {
		writeReadError(w, err)
		return
	}
	w.Header().Set("X-Lab-Beacon", "accepted")
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleSlow(w http.ResponseWriter, r *http.Request) {
	requested := boundedInt(r.URL.Query().Get("ms"), 250, 0, int(s.cfg.MaxDelay.Milliseconds()))
	timer := time.NewTimer(time.Duration(requested) * time.Millisecond)
	defer timer.Stop()

	select {
	case <-r.Context().Done():
		return
	case <-timer.C:
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         true,
			"delayed_ms": requested,
			"request_id": requestIDFromContext(r.Context()),
		})
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	code, err := strconv.Atoi(r.PathValue("code"))
	if err != nil || !allowedStatus(code) {
		writeError(w, http.StatusBadRequest, "unsupported status; use 200, 204, 400, 401, 403, 404, 409, 418, 429, 500, 502 or 503")
		return
	}
	if code == http.StatusNoContent {
		writeJSON(w, code, nil)
		return
	}
	writeJSON(w, code, map[string]any{
		"ok":               code < 400,
		"simulated_status": code,
		"request_id":       requestIDFromContext(r.Context()),
	})
}

func (s *Server) handleProtected(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"zone":       "protected-admin",
		"message":    "Origin allowed the request. Configure an SWS rule for this path to test edge blocking.",
		"request_id": requestIDFromContext(r.Context()),
	})
}

func requestMediaType(r *http.Request) string {
	value := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return ""
	}
	return strings.ToLower(mediaType)
}

func decodeSingleJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request contains more than one JSON value")
		}
		return err
	}
	return nil
}

func copyValues(source map[string][]string, maxKeys, maxValues int) map[string][]string {
	result := make(map[string][]string)
	keys := 0
	for key, values := range source {
		if keys >= maxKeys {
			break
		}
		if len(values) > maxValues {
			values = values[:maxValues]
		}
		result[key] = append([]string(nil), values...)
		keys++
	}
	return result
}

func boundedInt(raw string, fallback, min, max int) int {
	if fallback < min {
		fallback = min
	}
	if fallback > max {
		fallback = max
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min {
		return fallback
	}
	if value > max {
		return max
	}
	return value
}

func allowedStatus(code int) bool {
	switch code {
	case 200, 204, 400, 401, 403, 404, 409, 418, 429, 500, 502, 503:
		return true
	default:
		return false
	}
}

func (s *Server) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.cfg.TrustProxyHeaders && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
