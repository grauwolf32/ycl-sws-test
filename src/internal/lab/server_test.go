package lab

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	application, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return application.Handler()
}

func performRequest(t *testing.T, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeResponse(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, recorder.Body.String())
	}
	return result
}

func TestIndexAndOriginHeaders(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AppName = "Custom SWS Lab"
	handler := testHandler(t, cfg)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := performRequest(t, handler, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), "Custom SWS Lab") {
		t.Fatalf("index does not contain configured app name")
	}
	if got := recorder.Header().Get("X-Lab-Response"); got != "origin" {
		t.Fatalf("X-Lab-Response = %q, want origin", got)
	}
	if got := recorder.Header().Get("X-Request-ID"); !strings.HasPrefix(got, "lab-") {
		t.Fatalf("generated X-Request-ID = %q", got)
	}
	if got := recorder.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("Content-Security-Policy is missing")
	}

	assetRequest := httptest.NewRequest(http.MethodGet, "/assets/style.css", nil)
	assetRecorder := performRequest(t, handler, assetRequest)
	if assetRecorder.Code != http.StatusOK {
		t.Fatalf("asset status = %d, want %d", assetRecorder.Code, http.StatusOK)
	}
	if !strings.Contains(assetRecorder.Body.String(), "--accent") {
		t.Fatal("embedded stylesheet was not served")
	}
}

func TestEchoTreatsPayloadAsData(t *testing.T) {
	handler := testHandler(t, DefaultConfig())
	payload := `<script>alert("test")</script>' OR 1=1 --`
	request := httptest.NewRequest(http.MethodGet, "/api/echo?value="+url.QueryEscape(payload), nil)
	recorder := performRequest(t, handler, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	result := decodeResponse(t, recorder)
	if got := result["value"]; got != payload {
		t.Fatalf("value = %q, want %q", got, payload)
	}
	if got := result["executed"]; got != false {
		t.Fatalf("executed = %v, want false", got)
	}
}

func TestWAFFormAndJSON(t *testing.T) {
	handler := testHandler(t, DefaultConfig())

	form := url.Values{"comment": {"../../etc/passwd"}}
	formRequest := httptest.NewRequest(http.MethodPost, "/api/waf/form", strings.NewReader(form.Encode()))
	formRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formRecorder := performRequest(t, handler, formRequest)
	if formRecorder.Code != http.StatusOK {
		t.Fatalf("form status = %d, want %d: %s", formRecorder.Code, http.StatusOK, formRecorder.Body.String())
	}
	formResult := decodeResponse(t, formRecorder)
	if formResult["executed"] != false || formResult["stored"] != false {
		t.Fatalf("unsafe form response: %#v", formResult)
	}

	jsonRequest := httptest.NewRequest(http.MethodPost, "/api/waf/json", strings.NewReader(`{"query":"' OR '1'='1"}`))
	jsonRequest.Header.Set("Content-Type", "application/json")
	jsonRecorder := performRequest(t, handler, jsonRequest)
	if jsonRecorder.Code != http.StatusOK {
		t.Fatalf("JSON status = %d, want %d: %s", jsonRecorder.Code, http.StatusOK, jsonRecorder.Body.String())
	}
	jsonResult := decodeResponse(t, jsonRecorder)
	if jsonResult["executed"] != false || jsonResult["stored"] != false {
		t.Fatalf("unsafe JSON response: %#v", jsonResult)
	}
}

func TestUploadIsHashedAndDiscarded(t *testing.T) {
	handler := testHandler(t, DefaultConfig())
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("document", "sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(part, "test file"); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/waf/upload", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	recorder := performRequest(t, handler, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	result := decodeResponse(t, recorder)
	if result["stored"] != false {
		t.Fatalf("stored = %v, want false", result["stored"])
	}
	parts, ok := result["parts"].([]any)
	if !ok || len(parts) != 1 {
		t.Fatalf("parts = %#v, want one part", result["parts"])
	}
}

func TestBodyLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBodyBytes = 1024
	handler := testHandler(t, cfg)

	request := httptest.NewRequest(http.MethodPost, "/api/echo", strings.NewReader(strings.Repeat("x", 2048)))
	request.Header.Set("Content-Type", "text/plain")
	recorder := performRequest(t, handler, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusRequestEntityTooLarge, recorder.Body.String())
	}
}

func TestProxyHeaderTrust(t *testing.T) {
	tests := []struct {
		name       string
		trustProxy bool
		wantIP     string
	}{
		{name: "disabled", trustProxy: false, wantIP: "10.0.0.8"},
		{name: "enabled", trustProxy: true, wantIP: "203.0.113.17"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TrustProxyHeaders = test.trustProxy
			handler := testHandler(t, cfg)
			request := httptest.NewRequest(http.MethodGet, "/api/inspect", nil)
			request.RemoteAddr = "10.0.0.8:54321"
			request.Header.Set("X-Forwarded-For", "203.0.113.17, 198.51.100.4")
			recorder := performRequest(t, handler, request)
			result := decodeResponse(t, recorder)
			if got := result["effective_client_ip"]; got != test.wantIP {
				t.Fatalf("effective_client_ip = %q, want %q", got, test.wantIP)
			}
		})
	}
}

func TestLoginAndStatusRoutes(t *testing.T) {
	handler := testHandler(t, DefaultConfig())

	loginRequest := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"demo","password":"demo"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRecorder := performRequest(t, handler, loginRequest)
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d", loginRecorder.Code, http.StatusOK)
	}
	if len(loginRecorder.Result().Cookies()) != 1 {
		t.Fatalf("login cookies = %d, want 1", len(loginRecorder.Result().Cookies()))
	}

	statusRequest := httptest.NewRequest(http.MethodGet, "/api/status/429", nil)
	statusRecorder := performRequest(t, handler, statusRequest)
	if statusRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status route = %d, want %d", statusRecorder.Code, http.StatusTooManyRequests)
	}

	methodRequest := httptest.NewRequest(http.MethodDelete, "/api/catalog", nil)
	methodRecorder := performRequest(t, handler, methodRequest)
	if methodRecorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status = %d, want %d", methodRecorder.Code, http.StatusMethodNotAllowed)
	}
}

func TestBeaconReturnsEmptyNoContent(t *testing.T) {
	handler := testHandler(t, DefaultConfig())
	request := httptest.NewRequest(http.MethodPost, "/api/antibot/beacon", strings.NewReader(`{"event":"page_loaded"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := performRequest(t, handler, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "" {
		t.Fatalf("Content-Type = %q, want empty", got)
	}
	if got := recorder.Header().Get("X-Lab-Beacon"); got != "accepted" {
		t.Fatalf("X-Lab-Beacon = %q, want accepted", got)
	}
}

func TestStatsCountsRequestsByClientType(t *testing.T) {
	handler := testHandler(t, DefaultConfig())
	healthRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthRequest.Header.Set("User-Agent", "curl/8.0")
	performRequest(t, handler, healthRequest)

	statsRequest := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	statsRecorder := performRequest(t, handler, statsRequest)
	result := decodeResponse(t, statsRecorder)
	if got := result["requests_received"].(float64); got < 1 {
		t.Fatalf("requests_received = %v, want at least 1", got)
	}
	clientTypes := result["by_client_type"].(map[string]any)
	if got := clientTypes["http-client"]; got != float64(1) {
		t.Fatalf("http-client count = %v, want 1", got)
	}
}
