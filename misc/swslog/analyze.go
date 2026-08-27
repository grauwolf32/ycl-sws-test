package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

type ruleAccumulator struct {
	RuleSummary
}

type exclusionAccumulator struct {
	count   int
	ruleIDs map[string]struct{}
}

func analyzeLogs(parsed ParsedLogs, filters Filters, top int, clientMode string, report *CheckerReport) Analysis {
	selected := filterEvents(parsed.Events, filters)
	analysis := Analysis{
		SchemaVersion: analysisSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		InputRecords:  parsed.Records,
		Filters:       filters,
	}
	actions := make(map[string]int)
	verdicts := make(map[string]int)
	matchedRules := make(map[string]int)
	paths := make(map[string]int)
	hosts := make(map[string]int)
	clients := make(map[string]int)
	requests := make(map[string]struct{})
	rules := make(map[string]*ruleAccumulator)
	exclusions := make(map[string]*exclusionAccumulator)
	timeline := make(map[time.Time]*TimelineBucket)

	for _, event := range selected {
		analysis.Summary.SelectedEvents++
		switch event.Evaluation {
		case "active":
			analysis.Summary.ActiveEvaluations++
		case "dry-run":
			analysis.Summary.DryRunEvaluations++
			if isDeny(event.Verdict) {
				analysis.Summary.DryRunWouldDeny++
			}
		default:
			analysis.Summary.UnclassifiedEvents++
		}
		actions[displayValue(event.Action)]++
		verdicts[displayValue(event.Verdict)]++
		if event.RequestID != "" {
			requests[event.RequestID] = struct{}{}
		}
		if event.MatchedRule != "" {
			name := event.MatchedRule
			if event.MatchedRuleType != "" {
				name = event.MatchedRuleType + ":" + name
			}
			matchedRules[name]++
		}
		if event.Path != "" {
			name := strings.TrimSpace(event.Method + " " + routePath(event.Path))
			paths[name]++
		}
		if event.Host != "" {
			hosts[event.Host]++
		}
		if event.ClientIP != "" && clientMode != "omit" {
			identity := event.ClientIP
			if clientMode == "masked" {
				identity = maskedClientID(event.ClientIP)
			}
			clients[identity]++
		}
		if event.WAFScore > analysis.Summary.MaxWAFScore {
			analysis.Summary.MaxWAFScore = event.WAFScore
		}
		for _, hit := range event.Rules {
			analysis.Summary.RuleMatches++
			key := hit.RuleSetID + "\x00" + hit.RuleGroupID + "\x00" + hit.Group + "\x00" + hit.RuleID
			item := rules[key]
			if item == nil {
				item = &ruleAccumulator{RuleSummary: RuleSummary{
					RuleID: hit.RuleID, RuleSetID: hit.RuleSetID,
					RuleGroupID: hit.RuleGroupID, Group: hit.Group,
				}}
				rules[key] = item
			}
			item.Count++
			item.TotalScore += hit.Score
			if hit.Score > item.MaxScore {
				item.MaxScore = hit.Score
			}
			if hit.Blocking {
				item.BlockingCount++
			}
			if event.Evaluation == "dry-run" {
				item.DryRunCount++
			}
		}
		if event.Evaluation != "dry-run" && isAllow(event.Action) && len(event.Rules) != 0 {
			analysis.Summary.AllowedWithWAFMatch++
		}
		if event.Evaluation != "dry-run" && isDeny(event.Action) && len(event.Rules) == 0 {
			analysis.Summary.DeniedWithoutWAFMatch++
		}
		for _, exclusion := range event.Exclusions {
			item := exclusions[exclusion.Name]
			if item == nil {
				item = &exclusionAccumulator{ruleIDs: make(map[string]struct{})}
				exclusions[exclusion.Name] = item
			}
			item.count++
			for _, ruleID := range exclusion.RuleIDs {
				item.ruleIDs[ruleID] = struct{}{}
			}
		}
		if !event.Timestamp.IsZero() {
			hour := event.Timestamp.UTC().Truncate(time.Hour)
			bucket := timeline[hour]
			if bucket == nil {
				bucket = &TimelineBucket{Hour: hour}
				timeline[hour] = bucket
			}
			bucket.Events++
			if isDeny(event.Action) || (event.Evaluation == "active" && isDeny(event.Verdict)) {
				bucket.Denied++
			}
			if isCaptcha(event.Action) || (event.Evaluation == "active" && isCaptcha(event.Verdict)) {
				bucket.Captcha++
			}
			if event.Evaluation == "dry-run" {
				bucket.DryRun++
			}
			bucket.RuleMatches += len(event.Rules)
		}
	}
	analysis.Summary.DistinctRequests = len(requests)
	analysis.Actions = sortedCounts(actions, 0)
	analysis.Verdicts = sortedCounts(verdicts, 0)
	analysis.MatchedRules = sortedCounts(matchedRules, top)
	analysis.TopPaths = sortedCounts(paths, top)
	analysis.TopHosts = sortedCounts(hosts, top)
	analysis.TopClients = sortedCounts(clients, top)

	for _, item := range rules {
		analysis.TopWAFRules = append(analysis.TopWAFRules, item.RuleSummary)
	}
	sort.Slice(analysis.TopWAFRules, func(i, j int) bool {
		if analysis.TopWAFRules[i].Count != analysis.TopWAFRules[j].Count {
			return analysis.TopWAFRules[i].Count > analysis.TopWAFRules[j].Count
		}
		if analysis.TopWAFRules[i].TotalScore != analysis.TopWAFRules[j].TotalScore {
			return analysis.TopWAFRules[i].TotalScore > analysis.TopWAFRules[j].TotalScore
		}
		return analysis.TopWAFRules[i].RuleID < analysis.TopWAFRules[j].RuleID
	})
	if len(analysis.TopWAFRules) > top {
		analysis.TopWAFRules = analysis.TopWAFRules[:top]
	}

	for name, item := range exclusions {
		ruleIDs := mapKeys(item.ruleIDs)
		analysis.Exclusions = append(analysis.Exclusions, ExclusionSummary{Name: name, Count: item.count, RuleIDs: ruleIDs})
	}
	sort.Slice(analysis.Exclusions, func(i, j int) bool {
		if analysis.Exclusions[i].Count != analysis.Exclusions[j].Count {
			return analysis.Exclusions[i].Count > analysis.Exclusions[j].Count
		}
		return analysis.Exclusions[i].Name < analysis.Exclusions[j].Name
	})
	if len(analysis.Exclusions) > top {
		analysis.Exclusions = analysis.Exclusions[:top]
	}

	for _, bucket := range timeline {
		analysis.Timeline = append(analysis.Timeline, *bucket)
	}
	sort.Slice(analysis.Timeline, func(i, j int) bool { return analysis.Timeline[i].Hour.Before(analysis.Timeline[j].Hour) })
	if report != nil {
		correlation := correlate(*report, selected)
		analysis.Correlation = &correlation
	}
	return analysis
}

func filterEvents(events []Event, filters Filters) []Event {
	result := make([]Event, 0, len(events))
	for _, event := range events {
		if !filters.Since.IsZero() && (event.Timestamp.IsZero() || event.Timestamp.Before(filters.Since)) {
			continue
		}
		if !filters.Until.IsZero() && (event.Timestamp.IsZero() || !event.Timestamp.Before(filters.Until)) {
			continue
		}
		if filters.RequestIDPrefix != "" && !strings.HasPrefix(event.RequestID, filters.RequestIDPrefix) {
			continue
		}
		if len(filters.Actions) != 0 {
			_, actionOK := filters.Actions[strings.ToUpper(event.Action)]
			_, verdictOK := filters.Actions[strings.ToUpper(event.Verdict)]
			if !actionOK && !verdictOK {
				continue
			}
		}
		result = append(result, event)
	}
	return result
}

func correlate(report CheckerReport, events []Event) CorrelationAnalysis {
	byRequest := make(map[string][]Event)
	for _, event := range events {
		if event.RequestID != "" {
			byRequest[event.RequestID] = append(byRequest[event.RequestID], event)
		}
	}
	result := CorrelationAnalysis{RunID: report.RunID}
	result.Summary.Total = len(report.Results)
	for _, test := range report.Results {
		logs := byRequest[test.RequestID]
		item := CorrelatedCase{
			Name: test.Name, Category: test.Category, RequestID: test.RequestID,
			HTTPStatus: test.Status, HTTPDecision: test.Decision, ExpectedDecision: test.ExpectedDecision,
			LogEvents: len(logs),
		}
		if len(logs) == 0 {
			item.Status = "missing"
			result.Summary.Missing++
			result.Cases = append(result.Cases, item)
			continue
		}
		actions := make(map[string]struct{})
		activeVerdicts := make(map[string]struct{})
		dryVerdicts := make(map[string]struct{})
		ruleIDs := make(map[string]struct{})
		for _, event := range logs {
			if event.Action != "" {
				actions[event.Action] = struct{}{}
			}
			if event.Verdict != "" {
				if event.Evaluation == "dry-run" {
					dryVerdicts[event.Verdict] = struct{}{}
				} else {
					activeVerdicts[event.Verdict] = struct{}{}
				}
			}
			for _, rule := range event.Rules {
				ruleIDs[rule.RuleID] = struct{}{}
			}
			if event.WAFScore > item.MaxWAFScore {
				item.MaxWAFScore = event.WAFScore
			}
		}
		item.Actions = mapKeys(actions)
		item.ActiveVerdicts = mapKeys(activeVerdicts)
		item.DryRunVerdicts = mapKeys(dryVerdicts)
		item.RuleIDs = mapKeys(ruleIDs)
		item.LogDecision = observedDecision(logs)
		if !comparableDecision(test.Decision) || !comparableDecision(item.LogDecision) {
			item.Status = "inconclusive"
			result.Summary.Inconclusive++
		} else if test.Decision != item.LogDecision {
			item.Status = "conflict"
			result.Summary.Conflicts++
		} else {
			item.Status = "matched"
			result.Summary.Matched++
		}
		result.Cases = append(result.Cases, item)
	}
	return result
}

func observedDecision(events []Event) string {
	allow := false
	for _, event := range events {
		if isDeny(event.Action) || (event.Evaluation != "dry-run" && isDeny(event.Verdict)) {
			return "block"
		}
		if isCaptcha(event.Action) || (event.Evaluation != "dry-run" && isCaptcha(event.Verdict)) {
			return "captcha"
		}
		if isAllow(event.Action) || (event.Evaluation != "dry-run" && isAllow(event.Verdict)) {
			allow = true
		}
	}
	if allow {
		return "allow"
	}
	return "unknown"
}

func comparableDecision(value string) bool {
	return value == "allow" || value == "block" || value == "captcha"
}

func isDeny(value string) bool {
	value = strings.ToUpper(value)
	return value == "DENY" || value == "BLOCK" || value == "BLOCKED" || value == "REJECT"
}

func isCaptcha(value string) bool {
	return strings.Contains(strings.ToUpper(value), "CAPTCHA")
}

func isAllow(value string) bool {
	value = strings.ToUpper(value)
	return value == "ALLOW" || value == "PASS" || value == "ACCEPT"
}

func sortedCounts(values map[string]int, limit int) []CountItem {
	result := make([]CountItem, 0, len(values))
	for name, count := range values {
		result = append(result, CountItem{Name: name, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Name < result[j].Name
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func displayValue(value string) string {
	if value == "" {
		return "(empty)"
	}
	return value
}

func maskedClientID(value string) string {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err == nil {
		bits := 48
		if address.Is4() {
			bits = 24
		}
		return netip.PrefixFrom(address, bits).Masked().String()
	}
	hash := sha256.Sum256([]byte(value))
	return "opaque-" + hex.EncodeToString(hash[:4])
}

func routePath(value string) string {
	if parsed, err := url.Parse(value); err == nil {
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		return path
	}
	if path, _, found := strings.Cut(value, "?"); found {
		return path
	}
	if path, _, found := strings.Cut(value, "#"); found {
		return path
	}
	return value
}
