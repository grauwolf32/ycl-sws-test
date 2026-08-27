package main

import (
	"strings"
	"testing"
	"time"
)

const activeLog = `{
  "uid": "entry-active",
  "timestamp": "2026-08-28T10:00:00Z",
  "json_payload": {
    "client_ip": "192.0.2.44",
    "labels.action": "DENY",
    "labels.alb_request_id": "run-01-xss",
    "labels.http_host": "app.example.test",
    "labels.http_method": "GET",
    "labels.http_path": "/search?value=test",
    "labels.security_profile_id": "profile-1",
    "matched_rule_name": "waf-api",
    "matched_rule_type": "WAF",
    "matched_rule_verdict": "DENY",
    "waf_profile_id": "waf-profile-1",
    "waf_matched_rules": {
      "OWASP_CRS_4_0_0": {
        "rules": [{
          "rule_id": "owasp-crs-v4.0.0-id941100-attack-xss",
          "score": 5,
          "is_blocking_rule": false,
          "matched_data_value": "must-not-be-exported"
        }]
      }
    },
    "waf_matched_exclusion_rules": [{
      "exclusion_rule_name": "health-check",
      "excluded_rule_ids": ["rule-a"]
    }]
  }
}`

const dryRunLog = `{
  "uid": "entry-dry",
  "timestamp": "2026-08-28T10:01:00Z",
  "json_payload": {
    "labels": {
      "action": "ALLOW",
      "alb_request_id": "run-02-sqli",
      "http_method": "POST",
      "http_path": "/login"
    },
    "smartwebsecurity": {
      "dry_run_matched_rule": {
        "name": "waf-api-dry",
        "rule_type": "WAF",
        "verdict": "DENY"
      },
      "dry_run_waf_matched_rules": {
        "OWASP_CRS_4_0_0": {
          "rules": [{"rule_id": "sqli-942100", "score": "5", "is_blocking_rule": true}]
        }
      }
    }
  }
}`

func TestParseArrayAndNormalize(t *testing.T) {
	t.Parallel()
	parsed, err := parseLogs(strings.NewReader("[" + activeLog + "," + dryRunLog + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Records != 2 || len(parsed.Events) != 2 {
		t.Fatalf("parsed = %d records, %d events", parsed.Records, len(parsed.Events))
	}
	active := parsed.Events[0]
	if active.Evaluation != "active" || active.Action != "DENY" || active.Verdict != "DENY" {
		t.Fatalf("active event = %+v", active)
	}
	if active.WAFScore != 5 || len(active.Rules) != 1 || active.Rules[0].RuleID != "owasp-crs-v4.0.0-id941100-attack-xss" {
		t.Fatalf("active WAF data = score %d, rules %+v", active.WAFScore, active.Rules)
	}
	if active.Rules[0].RuleSetID != "OWASP_CRS_4_0_0" {
		t.Fatalf("active rule set = %q", active.Rules[0].RuleSetID)
	}
	if len(active.Exclusions) != 1 || active.Exclusions[0].Name != "health-check" {
		t.Fatalf("active exclusions = %+v", active.Exclusions)
	}
	dry := parsed.Events[1]
	if dry.Evaluation != "dry-run" || dry.Action != "ALLOW" || dry.Verdict != "DENY" || dry.RequestID != "run-02-sqli" {
		t.Fatalf("dry-run event = %+v", dry)
	}
	if dry.WAFScore != 5 || len(dry.Rules) != 1 || !dry.Rules[0].Blocking {
		t.Fatalf("dry-run WAF data = score %d, rules %+v", dry.WAFScore, dry.Rules)
	}
}

func TestExtractYandexRuleIdentifiers(t *testing.T) {
	t.Parallel()
	value := map[string]any{
		"YARS_0_1_1": map[string]any{
			"rule_groups": []any{map[string]any{
				"rule_group_id": "yars-group-xss",
				"rules": []any{map[string]any{
					"rule_id": "yars-v0.1.1-id8010001-attack-xss",
					"score":   float64(5),
				}},
			}},
		},
	}
	rules := extractRules(value)
	if len(rules) != 1 {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].RuleSetID != "YARS_0_1_1" || rules[0].RuleGroupID != "yars-group-xss" {
		t.Fatalf("identifiers = %+v", rules[0])
	}
}

func TestParseJSONLAndWrapper(t *testing.T) {
	t.Parallel()
	jsonl, err := parseLogs(strings.NewReader(activeLog + "\n" + dryRunLog + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if jsonl.Records != 2 || len(jsonl.Events) != 2 {
		t.Fatalf("JSONL parsed = %+v", jsonl)
	}
	wrapper, err := parseLogs(strings.NewReader(`{"entries":[` + activeLog + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if wrapper.Records != 1 || len(wrapper.Events) != 1 {
		t.Fatalf("wrapper parsed = %+v", wrapper)
	}
}

func TestExplicitTestIDWinsOverALBRequestID(t *testing.T) {
	t.Parallel()
	input := `{"json_payload":{"labels.action":"ALLOW","labels.alb_request_id":"alb-generated","headers":[{"name":"X-WAF-Test-ID","value":"comparison-01"}]}}`
	parsed, err := parseLogs(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Events) != 1 || parsed.Events[0].RequestID != "comparison-01" {
		t.Fatalf("events = %+v", parsed.Events)
	}
}

func TestAnalyzeAndCorrelate(t *testing.T) {
	t.Parallel()
	parsed, err := parseLogs(strings.NewReader("[" + activeLog + "," + dryRunLog + "]"))
	if err != nil {
		t.Fatal(err)
	}
	report := CheckerReport{
		SchemaVersion: "wafcheck/v1", RunID: "run",
		Results: []CheckerResult{
			{Name: "xss", RequestID: "run-01-xss", Decision: "block", ExpectedDecision: "block", Passed: true},
			{Name: "sqli-dry", RequestID: "run-02-sqli", Decision: "allow", ExpectedDecision: "block", Passed: false},
			{Name: "missing", RequestID: "run-03-missing", Decision: "allow", ExpectedDecision: "allow", Passed: true},
		},
	}
	analysis := analyzeLogs(parsed, Filters{}, 20, "masked", &report)
	if analysis.Summary.SelectedEvents != 2 || analysis.Summary.DryRunEvaluations != 1 || analysis.Summary.RuleMatches != 2 {
		t.Fatalf("summary = %+v", analysis.Summary)
	}
	if len(analysis.TopClients) != 1 || analysis.TopClients[0].Name != "192.0.2.0/24" {
		t.Fatalf("masked clients = %+v", analysis.TopClients)
	}
	if analysis.Correlation == nil {
		t.Fatal("correlation is nil")
	}
	if got := analysis.Correlation.Summary; got.Matched != 2 || got.Missing != 1 || got.Conflicts != 0 {
		t.Fatalf("correlation summary = %+v", got)
	}
	if got := analysis.Correlation.Cases[1]; got.LogDecision != "allow" || len(got.DryRunVerdicts) != 1 {
		t.Fatalf("dry-run correlation = %+v", got)
	}
}

func TestFilterEvents(t *testing.T) {
	t.Parallel()
	timestamp := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{Timestamp: timestamp, RequestID: "run-a", Action: "ALLOW"},
		{Timestamp: timestamp.Add(time.Hour), RequestID: "other-b", Action: "DENY"},
	}
	filters := Filters{
		Since: timestamp.Add(-time.Minute), Until: timestamp.Add(time.Minute), RequestIDPrefix: "run-",
		Actions: map[string]struct{}{"ALLOW": {}},
	}
	filtered := filterEvents(events, filters)
	if len(filtered) != 1 || filtered[0].RequestID != "run-a" {
		t.Fatalf("filtered = %+v", filtered)
	}
}

func TestExplicitZeroWAFScoreWinsOverRuleSum(t *testing.T) {
	t.Parallel()
	payload := map[string]any{"waf_score": float64(0)}
	rules := []RuleHit{{RuleID: "rule", Score: 5}}
	if got := extractWAFScore(payload, rules, false); got != 0 {
		t.Fatalf("score = %d, want explicit zero", got)
	}
}

func TestRoutePathRemovesQueryValues(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"/search?token=secret":                    "/search",
		"https://example.test/api/item?id=secret": "/api/item",
	} {
		if got := routePath(input); got != want {
			t.Errorf("routePath(%q) = %q, want %q", input, got, want)
		}
	}
}
