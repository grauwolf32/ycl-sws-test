package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type requestBody struct {
	Reader      io.Reader
	ContentType string
	Length      int64
	Closer      io.Closer
}

func runPlan(ctx context.Context, plan Plan, opts RunOptions) Report {
	started := time.Now().UTC()
	runID := opts.RunID
	if runID == "" {
		runID = "wafcheck-" + randomHex(6)
	}
	if opts.Parallel < 1 {
		opts.Parallel = 1
	}
	timeout, _ := time.ParseDuration(plan.Defaults.Timeout)
	if opts.TimeoutOverride > 0 {
		timeout = opts.TimeoutOverride
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.InsecureTLS} //nolint:gosec -- explicit CLI option
	client := &http.Client{Transport: transport, Timeout: timeout}
	if !plan.Defaults.FollowRedirects {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	}

	results := make([]CaseResult, len(plan.Cases))
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	for i := range plan.Cases {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = cancelledResult(plan.Cases[i], runID, ctx.Err())
				return
			}
			results[i] = runCase(ctx, client, plan, plan.Cases[i], runID, i, opts)
		}()
	}
	wg.Wait()
	transport.CloseIdleConnections()

	report := Report{
		SchemaVersion: reportSchemaVersion,
		RunID:         runID,
		Target:        plan.Target,
		StartedAt:     started,
		FinishedAt:    time.Now().UTC(),
		Results:       results,
		Summary: ReportSummary{
			Total:     len(results),
			Decisions: make(map[string]int),
		},
	}
	for _, result := range results {
		report.Summary.Decisions[result.Decision]++
		if result.Passed {
			report.Summary.Passed++
		} else {
			report.Summary.Failed++
		}
		if result.Error != "" {
			report.Summary.Errors++
		}
	}
	return report
}

func runCase(ctx context.Context, client *http.Client, plan Plan, tc TestCase, runID string, index int, opts RunOptions) CaseResult {
	started := time.Now().UTC()
	requestID := fmt.Sprintf("%s-%02d-%s", runID, index+1, slug(tc.Name))
	result := CaseResult{
		Name: tc.Name, Category: tc.Category, RequestID: requestID, StartedAt: started,
		Method: strings.ToUpper(tc.Method), Decision: "unknown", ExpectedDecision: tc.Expect.Decision,
	}
	finish := func() CaseResult {
		result.DurationMS = float64(time.Since(started).Microseconds()) / 1000
		return result
	}

	requestURL, err := buildURL(plan.Target, tc)
	if err != nil {
		result.Error = err.Error()
		return finish()
	}
	result.URL = requestURL
	body, err := makeRequestBody(tc.Body, opts.PlanDir)
	if err != nil {
		result.Error = err.Error()
		return finish()
	}
	if body.Closer != nil {
		defer body.Closer.Close()
	}
	req, err := http.NewRequestWithContext(ctx, result.Method, requestURL, body.Reader)
	if err != nil {
		result.Error = err.Error()
		return finish()
	}
	if body.Length >= 0 {
		req.ContentLength = body.Length
	}
	for name, value := range plan.Defaults.Headers {
		setRequestHeader(req, name, value)
	}
	for name, value := range tc.Headers {
		setRequestHeader(req, name, value)
	}
	if body.ContentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", body.ContentType)
	}
	if req.Header.Get("X-Request-ID") == "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	if req.Header.Get("X-WAF-Test-ID") == "" {
		req.Header.Set("X-WAF-Test-ID", requestID)
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return finish()
	}
	defer resp.Body.Close()
	result.Status = resp.StatusCode
	result.Decision = classifyResponse(resp, plan.Defaults)
	result.ResponseHeaders = selectedHeaders(resp.Header, plan.Defaults, tc.Expect)

	limit := plan.Defaults.MaxResponseBytes
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if readErr != nil {
		result.Error = fmt.Sprintf("read response: %v", readErr)
		return finish()
	}
	if int64(len(data)) > limit {
		result.ResponseTruncated = true
		data = data[:limit]
	}
	if opts.CaptureBodyBytes > 0 {
		n := opts.CaptureBodyBytes
		if n > int64(len(data)) {
			n = int64(len(data))
		}
		result.ResponseSnippet = string(data[:n])
	}
	result.Reasons = checkExpectation(tc.Expect, result.Decision, resp.StatusCode, resp.Header)
	result.Passed = len(result.Reasons) == 0
	return finish()
}

func cancelledResult(tc TestCase, runID string, err error) CaseResult {
	return CaseResult{
		Name: tc.Name, Category: tc.Category, RequestID: runID + "-cancelled-" + slug(tc.Name),
		StartedAt: time.Now().UTC(), Method: tc.Method, Decision: "unknown",
		ExpectedDecision: tc.Expect.Decision, Error: err.Error(),
	}
}

func buildURL(target string, tc TestCase) (string, error) {
	base, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if tc.Path != "" {
		rel, err := url.Parse(tc.Path)
		if err != nil {
			return "", err
		}
		base = base.ResolveReference(rel)
	}
	query := base.Query()
	keys := make([]string, 0, len(tc.Query))
	for key := range tc.Query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		query.Del(key)
		for _, value := range tc.Query[key] {
			query.Add(key, value)
		}
	}
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func makeRequestBody(spec *BodySpec, planDir string) (requestBody, error) {
	if spec == nil {
		return requestBody{Length: 0}, nil
	}
	contentType := spec.ContentType
	switch {
	case spec.Raw != nil:
		data := []byte(*spec.Raw)
		return requestBody{Reader: bytes.NewReader(data), ContentType: contentType, Length: int64(len(data))}, nil
	case len(spec.JSON) != 0:
		if contentType == "" {
			contentType = "application/json"
		}
		data := []byte(spec.JSON)
		return requestBody{Reader: bytes.NewReader(data), ContentType: contentType, Length: int64(len(data))}, nil
	case spec.Form != nil:
		values := make(url.Values, len(spec.Form))
		for key, value := range spec.Form {
			values.Set(key, value)
		}
		data := []byte(values.Encode())
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
		}
		return requestBody{Reader: bytes.NewReader(data), ContentType: contentType, Length: int64(len(data))}, nil
	case spec.File != "":
		path := resolvePlanPath(planDir, spec.File)
		file, err := os.Open(path)
		if err != nil {
			return requestBody{}, fmt.Errorf("open body file: %w", err)
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return requestBody{}, fmt.Errorf("stat body file: %w", err)
		}
		if info.Size() > maxRequestBody {
			file.Close()
			return requestBody{}, fmt.Errorf("body file exceeds %d bytes", maxRequestBody)
		}
		return requestBody{Reader: file, ContentType: contentType, Length: info.Size(), Closer: file}, nil
	case spec.Multipart != nil:
		return makeMultipartBody(*spec.Multipart, contentType, planDir)
	case spec.Generated != nil:
		pattern := []byte(spec.Generated.Pattern)
		if len(pattern) == 0 {
			pattern = []byte("A")
		}
		if contentType == "" {
			contentType = spec.Generated.ContentType
		}
		return requestBody{
			Reader:      &repeatReader{pattern: pattern, remaining: spec.Generated.Bytes},
			ContentType: contentType, Length: spec.Generated.Bytes,
		}, nil
	default:
		return requestBody{}, errors.New("empty body specification")
	}
}

func makeMultipartBody(spec MultipartSpec, overrideContentType, planDir string) (requestBody, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	fieldNames := make([]string, 0, len(spec.Fields))
	for name := range spec.Fields {
		fieldNames = append(fieldNames, name)
	}
	sort.Strings(fieldNames)
	for _, name := range fieldNames {
		if err := writer.WriteField(name, spec.Fields[name]); err != nil {
			return requestBody{}, err
		}
	}
	for _, fileSpec := range spec.Files {
		path := resolvePlanPath(planDir, fileSpec.Path)
		file, err := os.Open(path)
		if err != nil {
			return requestBody{}, fmt.Errorf("open multipart file %q: %w", fileSpec.Path, err)
		}
		name := fileSpec.Name
		if name == "" {
			name = filepath.Base(path)
		}
		var part io.Writer
		if fileSpec.ContentType == "" {
			part, err = writer.CreateFormFile(fileSpec.Field, name)
		} else {
			headers := make(textproto.MIMEHeader)
			headers.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, fileSpec.Field, name))
			headers.Set("Content-Type", fileSpec.ContentType)
			part, err = writer.CreatePart(headers)
		}
		if err == nil {
			_, err = io.CopyN(part, file, maxRequestBody+1)
			if errors.Is(err, io.EOF) {
				err = nil
			}
		}
		file.Close()
		if err != nil {
			return requestBody{}, fmt.Errorf("copy multipart file %q: %w", fileSpec.Path, err)
		}
		if int64(buf.Len()) > maxRequestBody {
			return requestBody{}, fmt.Errorf("multipart body exceeds %d bytes", maxRequestBody)
		}
	}
	if err := writer.Close(); err != nil {
		return requestBody{}, err
	}
	if int64(buf.Len()) > maxRequestBody {
		return requestBody{}, fmt.Errorf("multipart body exceeds %d bytes", maxRequestBody)
	}
	contentType := writer.FormDataContentType()
	if overrideContentType != "" {
		contentType = overrideContentType
	}
	return requestBody{Reader: bytes.NewReader(buf.Bytes()), ContentType: contentType, Length: int64(buf.Len())}, nil
}

type repeatReader struct {
	pattern   []byte
	offset    int
	remaining int64
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = r.pattern[r.offset]
		r.offset = (r.offset + 1) % len(r.pattern)
	}
	r.remaining -= int64(len(p))
	return len(p), nil
}

func classifyResponse(resp *http.Response, defaults PlanDefaults) string {
	captchaHeader := strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Yandex-Captcha")))
	if captchaHeader != "" {
		if strings.Contains(captchaHeader, "captcha") || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
			return "captcha"
		}
		if strings.Contains(captchaHeader, "403") {
			return "block"
		}
	}
	if containsInt(defaults.CaptchaStatuses, resp.StatusCode) {
		return "captcha"
	}
	if containsInt(defaults.BlockStatuses, resp.StatusCode) {
		return "block"
	}
	if defaults.OriginHeader != "" {
		value := resp.Header.Get(defaults.OriginHeader)
		if value != "" && (defaults.OriginHeaderValue == "" || value == defaults.OriginHeaderValue) {
			return "allow"
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "allow"
	}
	return "unknown"
}

func checkExpectation(expect Expectation, decision string, status int, headers http.Header) []string {
	var reasons []string
	if expect.Decision != "" && expect.Decision != "any" && expect.Decision != decision {
		reasons = append(reasons, fmt.Sprintf("decision: got %s, want %s", decision, expect.Decision))
	}
	if len(expect.Statuses) > 0 && !containsInt(expect.Statuses, status) {
		reasons = append(reasons, fmt.Sprintf("status: got %d, want one of %v", status, expect.Statuses))
	}
	keys := make([]string, 0, len(expect.RequireHeaders))
	for key := range expect.RequireHeaders {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		got, want := headers.Get(key), expect.RequireHeaders[key]
		if got != want {
			reasons = append(reasons, fmt.Sprintf("header %s: got %q, want %q", key, got, want))
		}
	}
	for _, key := range expect.AbsentHeaders {
		if value := headers.Get(key); value != "" {
			reasons = append(reasons, fmt.Sprintf("header %s must be absent", key))
		}
	}
	return reasons
}

func selectedHeaders(headers http.Header, defaults PlanDefaults, expect Expectation) map[string][]string {
	wanted := map[string]struct{}{
		"Content-Type": {}, "Content-Length": {}, "Location": {}, "Server": {},
		"X-Request-ID": {}, "X-Cloud-Request-ID": {}, "X-Yandex-Captcha": {},
	}
	if defaults.OriginHeader != "" {
		wanted[http.CanonicalHeaderKey(defaults.OriginHeader)] = struct{}{}
	}
	for key := range expect.RequireHeaders {
		wanted[http.CanonicalHeaderKey(key)] = struct{}{}
	}
	for _, key := range expect.AbsentHeaders {
		wanted[http.CanonicalHeaderKey(key)] = struct{}{}
	}
	result := make(map[string][]string)
	for key := range wanted {
		if values := headers.Values(key); len(values) > 0 {
			result[key] = append([]string(nil), values...)
		}
	}
	return result
}

func setRequestHeader(request *http.Request, name, value string) {
	if strings.EqualFold(name, "Host") {
		request.Host = value
		return
	}
	request.Header.Set(name, value)
}

func resolvePlanPath(planDir, path string) string {
	if filepath.IsAbs(path) || planDir == "" {
		return path
	}
	return filepath.Join(planDir, path)
}

func containsInt(values []int, value int) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func randomHex(bytesCount int) string {
	buf := make([]byte, bytesCount)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(buf)
}

func slug(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	result := strings.Trim(b.String(), "-")
	if result == "" {
		return "case"
	}
	if len(result) > 40 {
		result = result[:40]
	}
	return result
}

func marshalReport(report Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
