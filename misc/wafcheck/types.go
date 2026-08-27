package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	reportSchemaVersion = "wafcheck/v1"
	defaultMaxResponse  = int64(64 << 10)
	maxRequestBody      = int64(64 << 20)
)

// StringList accepts either a JSON string or an array of strings. It keeps
// plans readable for the common case while still allowing repeated query keys.
type StringList []string

func (s *StringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("expected a string or an array of strings")
	}
	*s = many
	return nil
}

type Plan struct {
	SchemaVersion string       `json:"schema_version,omitempty"`
	Target        string       `json:"target,omitempty"`
	Defaults      PlanDefaults `json:"defaults,omitempty"`
	Cases         []TestCase   `json:"cases"`
}

type PlanDefaults struct {
	Headers           map[string]string `json:"headers,omitempty"`
	Timeout           string            `json:"timeout,omitempty"`
	BlockStatuses     []int             `json:"block_statuses,omitempty"`
	CaptchaStatuses   []int             `json:"captcha_statuses,omitempty"`
	OriginHeader      string            `json:"origin_header,omitempty"`
	OriginHeaderValue string            `json:"origin_header_value,omitempty"`
	FollowRedirects   bool              `json:"follow_redirects,omitempty"`
	MaxResponseBytes  int64             `json:"max_response_bytes,omitempty"`
}

type TestCase struct {
	Name     string                `json:"name"`
	Category string                `json:"category,omitempty"`
	Method   string                `json:"method,omitempty"`
	Path     string                `json:"path,omitempty"`
	Query    map[string]StringList `json:"query,omitempty"`
	Headers  map[string]string     `json:"headers,omitempty"`
	Body     *BodySpec             `json:"body,omitempty"`
	Expect   Expectation           `json:"expect,omitempty"`
}

type BodySpec struct {
	Raw         *string            `json:"raw,omitempty"`
	JSON        json.RawMessage    `json:"json,omitempty"`
	Form        map[string]string  `json:"form,omitempty"`
	File        string             `json:"file,omitempty"`
	Multipart   *MultipartSpec     `json:"multipart,omitempty"`
	Generated   *GeneratedBodySpec `json:"generated,omitempty"`
	ContentType string             `json:"content_type,omitempty"`
}

type MultipartSpec struct {
	Fields map[string]string `json:"fields,omitempty"`
	Files  []MultipartFile   `json:"files,omitempty"`
}

type MultipartFile struct {
	Field       string `json:"field"`
	Path        string `json:"path"`
	Name        string `json:"name,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

type GeneratedBodySpec struct {
	Bytes       int64  `json:"bytes"`
	Pattern     string `json:"pattern,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

type Expectation struct {
	Decision       string            `json:"decision,omitempty"`
	Statuses       []int             `json:"statuses,omitempty"`
	RequireHeaders map[string]string `json:"require_headers,omitempty"`
	AbsentHeaders  []string          `json:"absent_headers,omitempty"`
}

type RunOptions struct {
	Parallel         int
	InsecureTLS      bool
	CaptureBodyBytes int64
	RunID            string
	PlanDir          string
	TimeoutOverride  time.Duration
}

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	RunID         string        `json:"run_id"`
	Target        string        `json:"target"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Summary       ReportSummary `json:"summary"`
	Results       []CaseResult  `json:"results"`
}

type ReportSummary struct {
	Total     int            `json:"total"`
	Passed    int            `json:"passed"`
	Failed    int            `json:"failed"`
	Errors    int            `json:"errors"`
	Decisions map[string]int `json:"decisions"`
}

type CaseResult struct {
	Name              string              `json:"name"`
	Category          string              `json:"category,omitempty"`
	RequestID         string              `json:"request_id"`
	StartedAt         time.Time           `json:"started_at"`
	DurationMS        float64             `json:"duration_ms"`
	Method            string              `json:"method"`
	URL               string              `json:"url"`
	Status            int                 `json:"status,omitempty"`
	Decision          string              `json:"decision"`
	ExpectedDecision  string              `json:"expected_decision,omitempty"`
	Passed            bool                `json:"passed"`
	Reasons           []string            `json:"reasons,omitempty"`
	Error             string              `json:"error,omitempty"`
	ResponseHeaders   map[string][]string `json:"response_headers,omitempty"`
	ResponseSnippet   string              `json:"response_snippet,omitempty"`
	ResponseTruncated bool                `json:"response_truncated,omitempty"`
}

func loadPlan(path string) (Plan, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Plan{}, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var plan Plan
	if err := dec.Decode(&plan); err != nil {
		return Plan{}, "", fmt.Errorf("decode plan: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return Plan{}, "", fmt.Errorf("decode trailing data: %w", err)
	} else if err == nil {
		return Plan{}, "", errors.New("decode plan: multiple JSON values")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return Plan{}, "", err
	}
	return plan, filepath.Dir(abs), nil
}

func applyPlanDefaults(plan *Plan) {
	if plan.SchemaVersion == "" {
		plan.SchemaVersion = "wafcheck-plan/v1"
	}
	if plan.Defaults.Timeout == "" {
		plan.Defaults.Timeout = "15s"
	}
	if len(plan.Defaults.BlockStatuses) == 0 {
		plan.Defaults.BlockStatuses = []int{http.StatusForbidden}
	}
	if plan.Defaults.MaxResponseBytes == 0 {
		plan.Defaults.MaxResponseBytes = defaultMaxResponse
	}
	if plan.Defaults.Headers == nil {
		plan.Defaults.Headers = make(map[string]string)
	}
	if !hasHeader(plan.Defaults.Headers, "User-Agent") {
		plan.Defaults.Headers["User-Agent"] = "wafcheck/1"
	}
	for i := range plan.Cases {
		if plan.Cases[i].Method == "" {
			plan.Cases[i].Method = http.MethodGet
		}
		if plan.Cases[i].Expect.Decision == "" {
			plan.Cases[i].Expect.Decision = "any"
		}
	}
}

func hasHeader(headers map[string]string, wanted string) bool {
	for name := range headers {
		if strings.EqualFold(name, wanted) {
			return true
		}
	}
	return false
}

func validatePlan(plan Plan) error {
	if plan.SchemaVersion != "wafcheck-plan/v1" {
		return fmt.Errorf("unsupported schema_version %q", plan.SchemaVersion)
	}
	base, err := url.Parse(plan.Target)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return fmt.Errorf("target must be an absolute HTTP(S) URL")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return fmt.Errorf("unsupported target scheme %q", base.Scheme)
	}
	if len(plan.Cases) == 0 {
		return errors.New("plan has no cases")
	}
	if _, err := time.ParseDuration(plan.Defaults.Timeout); err != nil {
		return fmt.Errorf("defaults.timeout: %w", err)
	}
	if plan.Defaults.MaxResponseBytes < 1 || plan.Defaults.MaxResponseBytes > 16<<20 {
		return errors.New("defaults.max_response_bytes must be between 1 and 16777216")
	}
	if err := validateStatuses("defaults.block_statuses", plan.Defaults.BlockStatuses); err != nil {
		return err
	}
	if err := validateStatuses("defaults.captcha_statuses", plan.Defaults.CaptchaStatuses); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(plan.Cases))
	for i, tc := range plan.Cases {
		where := fmt.Sprintf("cases[%d]", i)
		if strings.TrimSpace(tc.Name) == "" {
			return fmt.Errorf("%s.name is required", where)
		}
		if _, ok := seen[tc.Name]; ok {
			return fmt.Errorf("duplicate case name %q", tc.Name)
		}
		seen[tc.Name] = struct{}{}
		if strings.TrimSpace(tc.Method) == "" || strings.ContainsAny(tc.Method, " \t\r\n") {
			return fmt.Errorf("%s.method is invalid", where)
		}
		if p, err := url.Parse(tc.Path); err != nil || p.IsAbs() || p.Host != "" {
			return fmt.Errorf("%s.path must be a relative URL reference", where)
		}
		switch tc.Expect.Decision {
		case "any", "allow", "block", "captcha", "unknown":
		default:
			return fmt.Errorf("%s.expect.decision: unsupported value %q", where, tc.Expect.Decision)
		}
		if err := validateStatuses(where+".expect.statuses", tc.Expect.Statuses); err != nil {
			return err
		}
		if tc.Body != nil {
			if err := validateBody(*tc.Body, where+".body"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateStatuses(where string, statuses []int) error {
	for _, status := range statuses {
		if status < 100 || status > 599 {
			return fmt.Errorf("%s contains invalid HTTP status %d", where, status)
		}
	}
	return nil
}

func validateBody(body BodySpec, where string) error {
	set := 0
	if body.Raw != nil {
		set++
	}
	if len(body.JSON) != 0 {
		set++
		if !json.Valid(body.JSON) {
			return fmt.Errorf("%s.json is invalid", where)
		}
	}
	if body.Form != nil {
		set++
	}
	if body.File != "" {
		set++
	}
	if body.Multipart != nil {
		set++
		for i, file := range body.Multipart.Files {
			if file.Field == "" || file.Path == "" {
				return fmt.Errorf("%s.multipart.files[%d] requires field and path", where, i)
			}
		}
	}
	if body.Generated != nil {
		set++
		if body.Generated.Bytes < 0 || body.Generated.Bytes > maxRequestBody {
			return fmt.Errorf("%s.generated.bytes must be between 0 and %d", where, maxRequestBody)
		}
	}
	if set != 1 {
		return fmt.Errorf("%s must set exactly one of raw, json, form, file, multipart, generated", where)
	}
	return nil
}

func builtInPlan(target, path string) Plan {
	plain := "wafcheck baseline"
	return Plan{
		SchemaVersion: "wafcheck-plan/v1",
		Target:        target,
		Defaults: PlanDefaults{
			Timeout:          "15s",
			BlockStatuses:    []int{http.StatusForbidden},
			MaxResponseBytes: defaultMaxResponse,
		},
		Cases: []TestCase{
			{
				Name: "baseline-query", Category: "baseline", Method: http.MethodGet, Path: path,
				Query:  map[string]StringList{"wafcheck": {plain}},
				Expect: Expectation{Decision: "allow"},
			},
			{
				Name: "xss-query", Category: "xss", Method: http.MethodGet, Path: path,
				Query:  map[string]StringList{"wafcheck": {"<script>alert('wafcheck')</script>"}},
				Expect: Expectation{Decision: "block"},
			},
			{
				Name: "sqli-query", Category: "sqli", Method: http.MethodGet, Path: path,
				Query:  map[string]StringList{"wafcheck": {"' OR 1=1 -- wafcheck"}},
				Expect: Expectation{Decision: "block"},
			},
			{
				Name: "traversal-query", Category: "path-traversal", Method: http.MethodGet, Path: path,
				Query:  map[string]StringList{"wafcheck": {"../../../../etc/passwd"}},
				Expect: Expectation{Decision: "block"},
			},
			{
				Name: "scanner-user-agent", Category: "scanner", Method: http.MethodGet, Path: path,
				Headers: map[string]string{"User-Agent": "sqlmap/wafcheck"},
				Expect:  Expectation{Decision: "block"},
			},
			{
				Name: "trace-method", Category: "method", Method: http.MethodTrace, Path: path,
				Expect: Expectation{Decision: "block"},
			},
			{
				Name: "body-over-1mib", Category: "body-size", Method: http.MethodPost, Path: path,
				Body:   &BodySpec{Generated: &GeneratedBodySpec{Bytes: (1 << 20) + 1, Pattern: "A", ContentType: "application/octet-stream"}},
				Expect: Expectation{Decision: "block"},
			},
		},
	}
}
