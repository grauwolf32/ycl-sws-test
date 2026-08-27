package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPlan(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Request-ID") == "" || request.Header.Get("X-WAF-Test-ID") == "" {
			t.Error("request correlation headers are missing")
		}
		if strings.Contains(request.URL.Query().Get("value"), "<script>") {
			writer.Header().Set("X-Yandex-Captcha", "403")
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writer.Header().Set("X-Origin", "application")
		_, _ = io.WriteString(writer, "origin response")
	}))
	defer server.Close()

	plan := Plan{
		SchemaVersion: "wafcheck-plan/v1",
		Target:        server.URL,
		Defaults: PlanDefaults{
			Timeout: "2s", BlockStatuses: []int{http.StatusForbidden},
			OriginHeader: "X-Origin", OriginHeaderValue: "application", MaxResponseBytes: 1024,
		},
		Cases: []TestCase{
			{
				Name: "baseline", Method: http.MethodGet,
				Query:  map[string]StringList{"value": {"plain"}},
				Expect: Expectation{Decision: "allow", Statuses: []int{http.StatusOK}, RequireHeaders: map[string]string{"X-Origin": "application"}},
			},
			{
				Name: "xss", Category: "xss", Method: http.MethodGet,
				Query:  map[string]StringList{"value": {"<script>alert(1)</script>"}},
				Expect: Expectation{Decision: "block", Statuses: []int{http.StatusForbidden}, AbsentHeaders: []string{"X-Origin"}},
			},
		},
	}
	report := runPlan(context.Background(), plan, RunOptions{Parallel: 2, RunID: "test-run"})
	if report.SchemaVersion != "wafcheck/v1" {
		t.Fatalf("schema version = %q", report.SchemaVersion)
	}
	if report.Summary.Passed != 2 || report.Summary.Failed != 0 || report.Summary.Errors != 0 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
	if got := report.Results[0].RequestID; got != "test-run-01-baseline" {
		t.Fatalf("request ID = %q", got)
	}
	if got := report.Results[1].Decision; got != "block" {
		t.Fatalf("attack decision = %q", got)
	}
	if got := report.Results[0].ResponseHeaders["X-Origin"]; len(got) != 1 || got[0] != "application" {
		t.Fatalf("selected response headers = %#v", report.Results[0].ResponseHeaders)
	}
}

func TestClassifyResponse(t *testing.T) {
	t.Parallel()
	defaults := PlanDefaults{BlockStatuses: []int{403}, CaptchaStatuses: []int{429}, OriginHeader: "X-Origin"}
	tests := []struct {
		name   string
		status int
		header http.Header
		want   string
	}{
		{name: "allow", status: 200, want: "allow"},
		{name: "origin marker", status: 404, header: http.Header{"X-Origin": {"app"}}, want: "allow"},
		{name: "block", status: 403, want: "block"},
		{name: "captcha status", status: 429, want: "captcha"},
		{name: "captcha header", status: 302, header: http.Header{"X-Yandex-Captcha": {"captcha"}}, want: "captcha"},
		{name: "unknown application error", status: 404, want: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{StatusCode: test.status, Header: test.header}
			if response.Header == nil {
				response.Header = make(http.Header)
			}
			if got := classifyResponse(response, defaults); got != test.want {
				t.Fatalf("classifyResponse() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGeneratedBody(t *testing.T) {
	t.Parallel()
	body, err := makeRequestBody(&BodySpec{Generated: &GeneratedBodySpec{Bytes: 7, Pattern: "ab"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(body.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "abababa"; got != want {
		t.Fatalf("generated body = %q, want %q", got, want)
	}
}

func TestValidateBodyRejectsAmbiguousSpec(t *testing.T) {
	t.Parallel()
	raw := "value"
	err := validateBody(BodySpec{Raw: &raw, Form: map[string]string{"x": "y"}}, "body")
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetRequestHost(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/path", nil)
	setRequestHeader(request, "host", "virtual.example")
	if request.Host != "virtual.example" {
		t.Fatalf("request host = %q", request.Host)
	}
}

func TestLoadPlanRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(`{"target":"https://example.test","cases":[]} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPlan(path); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("unexpected error: %v", err)
	}
}
