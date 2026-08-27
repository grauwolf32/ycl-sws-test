package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

func parseLogs(reader io.Reader) (ParsedLogs, error) {
	buffered := bufio.NewReader(reader)
	first, err := firstNonSpace(buffered)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return ParsedLogs{}, nil
		}
		return ParsedLogs{}, err
	}
	decoder := json.NewDecoder(buffered)
	var result ParsedLogs
	consume := func(raw json.RawMessage) error {
		records, err := unwrapRecords(raw)
		if err != nil {
			return err
		}
		for _, record := range records {
			events, err := normalizeRecord(record)
			if err != nil {
				return fmt.Errorf("record %d: %w", result.Records+1, err)
			}
			result.Records++
			result.Events = append(result.Events, events...)
		}
		return nil
	}

	if first == '[' {
		if _, err := decoder.Token(); err != nil {
			return ParsedLogs{}, err
		}
		for decoder.More() {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return ParsedLogs{}, err
			}
			if err := consume(raw); err != nil {
				return ParsedLogs{}, err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return ParsedLogs{}, err
		}
		var extra any
		if err := decoder.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
			return ParsedLogs{}, fmt.Errorf("trailing JSON: %w", err)
		} else if err == nil {
			return ParsedLogs{}, errors.New("trailing JSON value after array")
		}
		return result, nil
	}

	for {
		var raw json.RawMessage
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ParsedLogs{}, err
		}
		if err := consume(raw); err != nil {
			return ParsedLogs{}, err
		}
	}
	return result, nil
}

func firstNonSpace(reader *bufio.Reader) (byte, error) {
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if !isJSONSpace(value) {
			if err := reader.UnreadByte(); err != nil {
				return 0, err
			}
			return value, nil
		}
	}
}

func isJSONSpace(value byte) bool {
	return value == ' ' || value == '\n' || value == '\r' || value == '\t'
}

func unwrapRecords(raw json.RawMessage) ([]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, errors.New("log entry must be a JSON object")
	}
	if _, payload := object["json_payload"]; payload {
		return []json.RawMessage{raw}, nil
	}
	if _, payload := object["jsonPayload"]; payload {
		return []json.RawMessage{raw}, nil
	}
	for _, key := range []string{"entries", "records", "items", "logs"} {
		value, ok := object[key]
		if !ok {
			continue
		}
		var records []json.RawMessage
		if err := json.Unmarshal(value, &records); err != nil {
			return nil, fmt.Errorf("wrapper field %s: %w", key, err)
		}
		return records, nil
	}
	return []json.RawMessage{raw}, nil
}

func normalizeRecord(raw json.RawMessage) ([]Event, error) {
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	payload := root
	for _, key := range []string{"json_payload", "jsonPayload", "payload"} {
		if value, ok := root[key].(map[string]any); ok {
			payload = value
			break
		}
	}

	base := Event{
		Timestamp: parseTimestamp(firstValue(root, "timestamp", "time", "receive_timestamp", "receiveTimestamp")),
		UID:       stringValue(firstValue(root, "uid", "insert_id", "insertId")),
		Action: strings.ToUpper(stringValue(firstValue(payload,
			"labels.action", "action", "smartwebsecurity.action", "meta.action"))),
		SecurityProfileID: stringValue(firstValue(payload,
			"labels.security_profile_id", "security_profile_id", "smartwebsecurity.security_profile_id")),
		Host: strings.ToLower(stringValue(firstValue(payload,
			"labels.http_host", "http_host", "host", "http.host", "httpRequest.host"))),
		Method: strings.ToUpper(stringValue(firstValue(payload,
			"labels.http_method", "http_method", "method", "http.method", "httpRequest.requestMethod"))),
		Path: stringValue(firstValue(payload,
			"labels.http_path", "http_path", "path", "http.path", "httpRequest.requestUrl")),
		ClientIP: stringValue(firstValue(payload,
			"client_ip", "remote_ip", "source_ip", "httpRequest.remoteIp")),
		Country:  strings.ToUpper(stringValue(firstValue(payload, "country", "client_country"))),
		BotScore: numberValue(firstValue(payload, "bot_score", "smartwebsecurity.bot_score")),
	}
	// A test marker is more useful for cross-system correlation than the ALB's
	// own request ID. Normal production logs fall back to their native ID.
	base.RequestID = findHeaderValue(payload, "x-waf-test-id")
	if base.RequestID == "" {
		base.RequestID = stringValue(firstValue(payload,
			"labels.alb_request_id", "alb_request_id", "request_id", "requestId",
			"smartwebsecurity.request_id", "meta.request_id"))
	}
	if base.RequestID == "" {
		base.RequestID = findHeaderValue(payload, "x-request-id")
	}

	activeRulesValue, activeRulesFound := findKeyRecursive(payload, "waf_matched_rules")
	dryRulesValue, dryRulesFound := findKeyRecursive(payload, "dry_run_waf_matched_rules")
	activeExclusions, _ := findKeyRecursive(payload, "waf_matched_exclusion_rules")
	dryExclusions, _ := findKeyRecursive(payload, "dry_run_waf_matched_exclusion_rules")

	activeName := stringValue(firstValue(payload,
		"matched_rule_name", "matched_rule.name", "smartwebsecurity.matched_rule.name", "meta.matched_rule.name"))
	activeType := stringValue(firstValue(payload,
		"matched_rule_type", "matched_rule.rule_type", "smartwebsecurity.matched_rule.rule_type", "meta.matched_rule.rule_type"))
	activeVerdict := strings.ToUpper(stringValue(firstValue(payload,
		"matched_rule_verdict", "matched_rule.verdict", "smartwebsecurity.matched_rule.verdict", "meta.matched_rule.verdict")))
	activeProfile := stringValue(firstValue(payload,
		"waf_profile_id", "smartwebsecurity.waf_profile_id", "matched_rule.waf_profile_id"))

	dryName := stringValue(firstValue(payload,
		"dry_run_matched_rule_name", "dry_run_matched_rule.name", "smartwebsecurity.dry_run_matched_rule.name"))
	dryType := stringValue(firstValue(payload,
		"dry_run_matched_rule_type", "dry_run_matched_rule.rule_type", "smartwebsecurity.dry_run_matched_rule.rule_type"))
	dryVerdict := strings.ToUpper(stringValue(firstValue(payload,
		"dry_run_matched_rule_verdict", "dry_run_matched_rule.verdict", "smartwebsecurity.dry_run_matched_rule.verdict")))
	dryProfile := stringValue(firstValue(payload,
		"dry_run_waf_profile_id", "smartwebsecurity.dry_run_waf_profile_id", "dry_run_matched_rule.waf_profile_id"))

	var events []Event
	if activeName != "" || activeType != "" || activeVerdict != "" || activeRulesFound {
		event := base
		event.Evaluation = "active"
		event.MatchedRule = activeName
		event.MatchedRuleType = activeType
		event.Verdict = activeVerdict
		event.WAFProfileID = activeProfile
		event.Rules = extractRules(activeRulesValue)
		event.Exclusions = extractExclusions(activeExclusions)
		event.WAFScore = extractWAFScore(payload, event.Rules, false)
		events = append(events, event)
	}
	if dryName != "" || dryType != "" || dryVerdict != "" || dryRulesFound {
		event := base
		event.Evaluation = "dry-run"
		event.MatchedRule = dryName
		event.MatchedRuleType = dryType
		event.Verdict = dryVerdict
		event.WAFProfileID = dryProfile
		event.Rules = extractRules(dryRulesValue)
		event.Exclusions = extractExclusions(dryExclusions)
		event.WAFScore = extractWAFScore(payload, event.Rules, true)
		events = append(events, event)
	}
	if len(events) == 0 {
		base.Evaluation = "unclassified"
		base.Verdict = base.Action
		events = append(events, base)
	}
	return events, nil
}

func firstValue(object map[string]any, paths ...string) any {
	value, _ := lookupValue(object, paths...)
	return value
}

func lookupValue(object map[string]any, paths ...string) (any, bool) {
	for _, path := range paths {
		if value, ok := object[path]; ok {
			return value, true
		}
		parts := strings.Split(path, ".")
		var current any = object
		found := true
		for _, part := range parts {
			mapping, ok := current.(map[string]any)
			if !ok {
				found = false
				break
			}
			current, ok = mapping[part]
			if !ok {
				found = false
				break
			}
		}
		if found {
			return current, true
		}
	}
	return nil, false
}

func findKeyRecursive(value any, wanted string) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if value, ok := typed[wanted]; ok {
			return value, true
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if value, ok := findKeyRecursive(typed[key], wanted); ok {
				return value, true
			}
		}
	case []any:
		for _, item := range typed {
			if value, ok := findKeyRecursive(item, wanted); ok {
				return value, true
			}
		}
	}
	return nil, false
}

func extractRules(value any) []RuleHit {
	var result []RuleHit
	var walk func(any, string, string, string)
	walk = func(current any, group, ruleSetID, ruleGroupID string) {
		switch typed := current.(type) {
		case map[string]any:
			if explicit := stringValue(firstValue(typed, "rule_set_id", "ruleSetId")); explicit != "" {
				ruleSetID = explicit
			}
			if explicit := stringValue(firstValue(typed, "rule_group_id", "ruleGroupId")); explicit != "" {
				ruleGroupID = explicit
				group = explicit
			}
			ruleID := stringValue(firstValue(typed, "rule_id", "ruleId", "id"))
			if ruleID != "" {
				result = append(result, RuleHit{
					RuleSetID: ruleSetID, RuleGroupID: ruleGroupID, Group: group, RuleID: ruleID,
					Score: int(numberValue(firstValue(typed, "score", "anomaly_score", "anomalyScore"))),
					Blocking: boolValue(firstValue(typed,
						"is_blocking_rule", "blocking", "isBlockingRule")),
				})
				return
			}
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				nextGroup := group
				nextRuleSetID := ruleSetID
				nextRuleGroupID := ruleGroupID
				if looksLikeRuleSetID(key) {
					nextRuleSetID = key
				}
				if key != "rules" && key != "matches" && key != "items" {
					nextGroup = key
				}
				walk(typed[key], nextGroup, nextRuleSetID, nextRuleGroupID)
			}
		case []any:
			for _, item := range typed {
				walk(item, group, ruleSetID, ruleGroupID)
			}
		}
	}
	walk(value, "", "", "")
	return result
}

func looksLikeRuleSetID(value string) bool {
	upper := strings.ToUpper(value)
	return strings.HasPrefix(upper, "OWASP_CRS_") || strings.HasPrefix(upper, "YARS_")
}

func extractExclusions(value any) []ExclusionHit {
	var result []ExclusionHit
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			name := stringValue(firstValue(typed, "exclusion_rule_name", "name", "exclusionRuleName"))
			if name != "" {
				result = append(result, ExclusionHit{Name: name, RuleIDs: stringSlice(firstValue(typed,
					"excluded_rule_ids", "rule_ids", "excludedRuleIds"))})
				return
			}
			for _, item := range typed {
				walk(item)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(value)
	return result
}

func extractWAFScore(payload map[string]any, rules []RuleHit, dryRun bool) int {
	paths := []string{"waf_score", "waf_anomaly_score", "waf_profile_total_anomaly_score"}
	if dryRun {
		paths = []string{"dry_run_waf_score", "dry_run_waf_anomaly_score", "dry_run_waf_profile_total_anomaly_score"}
	}
	if scoreValue, ok := lookupValue(payload, paths...); ok {
		return int(numberValue(scoreValue))
	}
	for _, path := range paths {
		if scoreValue, ok := findKeyRecursive(payload, path); ok {
			return int(numberValue(scoreValue))
		}
	}
	total := 0
	for _, rule := range rules {
		total += rule.Score
	}
	return total
}

func findHeaderValue(value any, wanted string) string {
	wanted = strings.ToLower(wanted)
	var walk func(any) string
	walk = func(current any) string {
		switch typed := current.(type) {
		case map[string]any:
			for key, item := range typed {
				if strings.ToLower(key) == wanted {
					return stringValue(item)
				}
			}
			name := strings.ToLower(stringValue(firstValue(typed, "name", "key")))
			if name == wanted {
				return stringValue(firstValue(typed, "value", "values"))
			}
			for _, item := range typed {
				if found := walk(item); found != "" {
					return found
				}
			}
		case []any:
			for _, item := range typed {
				if found := walk(item); found != "" {
					return found
				}
			}
		}
		return ""
	}
	return walk(value)
}

func parseTimestamp(value any) time.Time {
	switch typed := value.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999Z07:00"} {
			if parsed, err := time.Parse(layout, typed); err == nil {
				return parsed.UTC()
			}
		}
	case json.Number:
		if seconds, err := strconv.ParseFloat(typed.String(), 64); err == nil {
			whole := int64(seconds)
			return time.Unix(whole, int64((seconds-float64(whole))*1e9)).UTC()
		}
	case float64:
		whole := int64(typed)
		return time.Unix(whole, int64((typed-float64(whole))*1e9)).UTC()
	}
	return time.Time{}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	case []any:
		if len(typed) > 0 {
			return stringValue(typed[0])
		}
	}
	return ""
}

func numberValue(value any) float64 {
	switch typed := value.(type) {
	case json.Number:
		result, _ := typed.Float64()
		return result
	case float64:
		return typed
	case int:
		return float64(typed)
	case string:
		result, _ := strconv.ParseFloat(typed, 64)
		return result
	}
	return 0
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		result, _ := strconv.ParseBool(typed)
		return result
	case json.Number:
		return typed.String() != "0"
	}
	return false
}

func stringSlice(value any) []string {
	switch typed := value.(type) {
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := stringValue(item); text != "" {
				result = append(result, text)
			}
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	case string:
		if typed != "" {
			return []string{typed}
		}
	}
	return nil
}
