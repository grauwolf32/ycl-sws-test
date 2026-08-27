package main

import "time"

const analysisSchemaVersion = "swslog/v1"

type ParsedLogs struct {
	Records int
	Events  []Event
}

// Event is a normalized SWS rule evaluation. One source log record may produce
// both an active and a dry-run event.
type Event struct {
	Timestamp         time.Time
	UID               string
	RequestID         string
	Action            string
	Verdict           string
	Evaluation        string
	MatchedRule       string
	MatchedRuleType   string
	WAFProfileID      string
	SecurityProfileID string
	Host              string
	Method            string
	Path              string
	ClientIP          string
	Country           string
	BotScore          float64
	WAFScore          int
	Rules             []RuleHit
	Exclusions        []ExclusionHit
}

type RuleHit struct {
	RuleSetID   string
	RuleGroupID string
	Group       string
	RuleID      string
	Score       int
	Blocking    bool
}

type ExclusionHit struct {
	Name    string
	RuleIDs []string
}

type Filters struct {
	Since           time.Time           `json:"since,omitzero"`
	Until           time.Time           `json:"until,omitzero"`
	RequestIDPrefix string              `json:"request_id_prefix,omitempty"`
	Actions         map[string]struct{} `json:"-"`
	ActionList      []string            `json:"actions,omitempty"`
}

type Analysis struct {
	SchemaVersion string               `json:"schema_version"`
	GeneratedAt   time.Time            `json:"generated_at"`
	InputRecords  int                  `json:"input_records"`
	Filters       Filters              `json:"filters,omitempty"`
	Summary       AnalysisSummary      `json:"summary"`
	Actions       []CountItem          `json:"actions,omitempty"`
	Verdicts      []CountItem          `json:"verdicts,omitempty"`
	MatchedRules  []CountItem          `json:"matched_rules,omitempty"`
	TopWAFRules   []RuleSummary        `json:"top_waf_rules,omitempty"`
	TopPaths      []CountItem          `json:"top_paths,omitempty"`
	TopHosts      []CountItem          `json:"top_hosts,omitempty"`
	TopClients    []CountItem          `json:"top_clients,omitempty"`
	Exclusions    []ExclusionSummary   `json:"exclusions,omitempty"`
	Timeline      []TimelineBucket     `json:"timeline,omitempty"`
	Correlation   *CorrelationAnalysis `json:"correlation,omitempty"`
}

type AnalysisSummary struct {
	SelectedEvents        int `json:"selected_events"`
	DistinctRequests      int `json:"distinct_requests"`
	ActiveEvaluations     int `json:"active_evaluations"`
	DryRunEvaluations     int `json:"dry_run_evaluations"`
	DryRunWouldDeny       int `json:"dry_run_would_deny"`
	AllowedWithWAFMatch   int `json:"allowed_with_waf_match"`
	DeniedWithoutWAFMatch int `json:"denied_without_waf_match"`
	UnclassifiedEvents    int `json:"unclassified_events"`
	RuleMatches           int `json:"rule_matches"`
	MaxWAFScore           int `json:"max_waf_score"`
}

type CountItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type RuleSummary struct {
	RuleID        string `json:"rule_id"`
	RuleSetID     string `json:"rule_set_id,omitempty"`
	RuleGroupID   string `json:"rule_group_id,omitempty"`
	Group         string `json:"group,omitempty"`
	Count         int    `json:"count"`
	TotalScore    int    `json:"total_score"`
	MaxScore      int    `json:"max_score"`
	BlockingCount int    `json:"blocking_count"`
	DryRunCount   int    `json:"dry_run_count"`
}

type ExclusionSummary struct {
	Name    string   `json:"name"`
	Count   int      `json:"count"`
	RuleIDs []string `json:"rule_ids,omitempty"`
}

type TimelineBucket struct {
	Hour        time.Time `json:"hour"`
	Events      int       `json:"events"`
	Denied      int       `json:"denied"`
	Captcha     int       `json:"captcha"`
	DryRun      int       `json:"dry_run"`
	RuleMatches int       `json:"rule_matches"`
}

type CheckerReport struct {
	SchemaVersion string          `json:"schema_version"`
	RunID         string          `json:"run_id"`
	Results       []CheckerResult `json:"results"`
}

type CheckerResult struct {
	Name             string `json:"name"`
	Category         string `json:"category,omitempty"`
	RequestID        string `json:"request_id"`
	Status           int    `json:"status,omitempty"`
	Decision         string `json:"decision"`
	ExpectedDecision string `json:"expected_decision,omitempty"`
	Passed           bool   `json:"passed"`
}

type CorrelationAnalysis struct {
	RunID   string             `json:"run_id"`
	Summary CorrelationSummary `json:"summary"`
	Cases   []CorrelatedCase   `json:"cases"`
}

type CorrelationSummary struct {
	Total        int `json:"total"`
	Matched      int `json:"matched"`
	Missing      int `json:"missing"`
	Conflicts    int `json:"conflicts"`
	Inconclusive int `json:"inconclusive"`
}

type CorrelatedCase struct {
	Name             string   `json:"name"`
	Category         string   `json:"category,omitempty"`
	RequestID        string   `json:"request_id"`
	HTTPStatus       int      `json:"http_status,omitempty"`
	HTTPDecision     string   `json:"http_decision"`
	ExpectedDecision string   `json:"expected_decision,omitempty"`
	LogDecision      string   `json:"log_decision,omitempty"`
	Actions          []string `json:"actions,omitempty"`
	ActiveVerdicts   []string `json:"active_verdicts,omitempty"`
	DryRunVerdicts   []string `json:"dry_run_verdicts,omitempty"`
	RuleIDs          []string `json:"rule_ids,omitempty"`
	MaxWAFScore      int      `json:"max_waf_score,omitempty"`
	LogEvents        int      `json:"log_events"`
	Status           string   `json:"status"`
}
