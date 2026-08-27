package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("swslog", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		input         = flags.String("input", "-", "input JSON array/JSONL file, or - for stdin")
		reportPath    = flags.String("report", "", "optional wafcheck/v1 JSON report for request correlation")
		output        = flags.String("output", "", "write the JSON analysis to this file")
		format        = flags.String("format", "text", "stdout format: text or json")
		sinceText     = flags.String("since", "", "RFC3339 time or duration ago, for example 24h")
		untilText     = flags.String("until", "", "RFC3339 time or duration ago")
		requestPrefix = flags.String("request-id-prefix", "", "only request IDs with this prefix")
		actionText    = flags.String("actions", "", "comma-separated actions or verdicts")
		top           = flags.Int("top", 20, "maximum rows in ranked sections")
		clientMode    = flags.String("client-ids", "masked", "client identifiers: masked, full, or omit")
		failMissing   = flags.Bool("fail-on-missing", false, "exit 1 when correlated requests have no logs")
		failConflict  = flags.Bool("fail-on-conflict", false, "exit 1 when HTTP and log decisions conflict")
		failUnknown   = flags.Bool("fail-on-inconclusive", false, "exit 1 when a correlated decision cannot be classified")
		failEmpty     = flags.Bool("fail-on-empty", false, "exit 1 when no events pass the filters")
	)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: swslog -input sws.json [-report wafcheck-report.json] [options]")
		fmt.Fprintln(stderr, "       yc logging read ... --format json | swslog -input -")
		fmt.Fprintln(stderr)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "-format must be text or json")
		return 2
	}
	if *top < 1 || *top > 1000 {
		fmt.Fprintln(stderr, "-top must be between 1 and 1000")
		return 2
	}
	if *clientMode != "masked" && *clientMode != "full" && *clientMode != "omit" {
		fmt.Fprintln(stderr, "-client-ids must be masked, full, or omit")
		return 2
	}

	now := time.Now().UTC()
	since, err := parseBoundary(*sinceText, now)
	if err != nil {
		fmt.Fprintf(stderr, "invalid -since: %v\n", err)
		return 2
	}
	until, err := parseBoundary(*untilText, now)
	if err != nil {
		fmt.Fprintf(stderr, "invalid -until: %v\n", err)
		return 2
	}
	if !since.IsZero() && !until.IsZero() && !since.Before(until) {
		fmt.Fprintln(stderr, "-since must be earlier than -until")
		return 2
	}
	filters := Filters{Since: since, Until: until, RequestIDPrefix: *requestPrefix}
	if *actionText != "" {
		filters.Actions = make(map[string]struct{})
		for _, item := range strings.Split(*actionText, ",") {
			item = strings.ToUpper(strings.TrimSpace(item))
			if item != "" {
				filters.Actions[item] = struct{}{}
				filters.ActionList = append(filters.ActionList, item)
			}
		}
		sort.Strings(filters.ActionList)
	}

	reader := stdin
	var inputFile *os.File
	if *input != "-" {
		inputFile, err = os.Open(*input)
		if err != nil {
			fmt.Fprintf(stderr, "open input: %v\n", err)
			return 2
		}
		defer inputFile.Close()
		reader = inputFile
	}
	parsed, err := parseLogs(reader)
	if err != nil {
		fmt.Fprintf(stderr, "parse logs: %v\n", err)
		return 2
	}

	var checker *CheckerReport
	if *reportPath != "" {
		loaded, err := loadCheckerReport(*reportPath)
		if err != nil {
			fmt.Fprintf(stderr, "load checker report: %v\n", err)
			return 2
		}
		checker = &loaded
	}
	analysis := analyzeLogs(parsed, filters, *top, *clientMode, checker)
	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encode analysis: %v\n", err)
		return 2
	}
	if *output != "" {
		if err := os.WriteFile(*output, append(data, '\n'), 0o600); err != nil {
			fmt.Fprintf(stderr, "write output: %v\n", err)
			return 2
		}
	}
	if *format == "json" {
		if _, err := stdout.Write(append(data, '\n')); err != nil {
			fmt.Fprintf(stderr, "write output: %v\n", err)
			return 2
		}
	} else {
		writeTextAnalysis(stdout, analysis, *output)
	}
	if analysis.Correlation != nil {
		if *failMissing && analysis.Correlation.Summary.Missing != 0 {
			return 1
		}
		if *failConflict && analysis.Correlation.Summary.Conflicts != 0 {
			return 1
		}
		if *failUnknown && analysis.Correlation.Summary.Inconclusive != 0 {
			return 1
		}
	}
	if *failEmpty && analysis.Summary.SelectedEvents == 0 {
		return 1
	}
	return 0
}

func loadCheckerReport(path string) (CheckerReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CheckerReport{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var report CheckerReport
	if err := decoder.Decode(&report); err != nil {
		return CheckerReport{}, err
	}
	if report.SchemaVersion != "wafcheck/v1" {
		return CheckerReport{}, fmt.Errorf("unsupported schema_version %q", report.SchemaVersion)
	}
	if len(report.Results) == 0 {
		return CheckerReport{}, errors.New("report contains no results")
	}
	return report, nil
}

func parseBoundary(value string, now time.Time) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return time.Time{}, errors.New("expected RFC3339 or a Go duration such as 24h")
	}
	if duration < 0 {
		return now.Add(duration), nil
	}
	return now.Add(-duration), nil
}

func writeTextAnalysis(out io.Writer, analysis Analysis, outputPath string) {
	fmt.Fprintf(out, "records: %d  selected evaluations: %d  requests: %d\n",
		analysis.InputRecords, analysis.Summary.SelectedEvents, analysis.Summary.DistinctRequests)
	fmt.Fprintf(out, "active: %d  dry-run: %d  unclassified: %d  WAF matches: %d  max score: %d\n",
		analysis.Summary.ActiveEvaluations, analysis.Summary.DryRunEvaluations,
		analysis.Summary.UnclassifiedEvents, analysis.Summary.RuleMatches, analysis.Summary.MaxWAFScore)
	fmt.Fprintf(out, "dry-run would deny: %d  allowed with WAF match: %d  denied without WAF match: %d\n",
		analysis.Summary.DryRunWouldDeny, analysis.Summary.AllowedWithWAFMatch,
		analysis.Summary.DeniedWithoutWAFMatch)
	writeCountSection(out, "actions", analysis.Actions)
	writeCountSection(out, "verdicts", analysis.Verdicts)
	writeCountSection(out, "matched security rules", analysis.MatchedRules)

	if len(analysis.TopWAFRules) != 0 {
		fmt.Fprintln(out, "\nWAF signatures:")
		writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "COUNT\tSCORE\tMAX\tBLOCKING\tDRY-RUN\tRULE SET\tRULE GROUP\tCONTAINER\tRULE ID")
		for _, rule := range analysis.TopWAFRules {
			fmt.Fprintf(writer, "%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\n",
				rule.Count, rule.TotalScore, rule.MaxScore, rule.BlockingCount, rule.DryRunCount,
				rule.RuleSetID, rule.RuleGroupID, rule.Group, rule.RuleID)
		}
		writer.Flush()
	}
	writeCountSection(out, "top paths", analysis.TopPaths)
	writeCountSection(out, "top hosts", analysis.TopHosts)
	writeCountSection(out, "top clients", analysis.TopClients)
	if len(analysis.Exclusions) != 0 {
		fmt.Fprintln(out, "\nmatched exclusions:")
		writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "COUNT\tEXCLUSION\tRULE IDS")
		for _, item := range analysis.Exclusions {
			fmt.Fprintf(writer, "%d\t%s\t%s\n", item.Count, item.Name, strings.Join(item.RuleIDs, ","))
		}
		writer.Flush()
	}
	if len(analysis.Timeline) != 0 {
		fmt.Fprintln(out, "\ntimeline (UTC):")
		writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "HOUR\tEVENTS\tDENIED\tCAPTCHA\tDRY-RUN\tRULE MATCHES")
		for _, item := range analysis.Timeline {
			fmt.Fprintf(writer, "%s\t%d\t%d\t%d\t%d\t%d\n", item.Hour.Format("2006-01-02 15:00"),
				item.Events, item.Denied, item.Captcha, item.DryRun, item.RuleMatches)
		}
		writer.Flush()
	}
	if analysis.Correlation != nil {
		correlation := analysis.Correlation
		fmt.Fprintf(out, "\ncorrelation run %s: %d matched, %d missing, %d conflicts, %d inconclusive\n",
			correlation.RunID, correlation.Summary.Matched, correlation.Summary.Missing,
			correlation.Summary.Conflicts, correlation.Summary.Inconclusive)
		writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "STATUS\tCASE\tHTTP\tLOG\tEVENTS\tMAX SCORE\tREQUEST ID")
		for _, item := range correlation.Cases {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
				strings.ToUpper(item.Status), item.Name, item.HTTPDecision, displayValue(item.LogDecision),
				item.LogEvents, item.MaxWAFScore, item.RequestID)
		}
		writer.Flush()
	}
	if outputPath != "" {
		fmt.Fprintf(out, "\njson analysis: %s\n", outputPath)
	}
}

func writeCountSection(out io.Writer, title string, items []CountItem) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%s:\n", title)
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "COUNT\tVALUE")
	for _, item := range items {
		fmt.Fprintf(writer, "%d\t%s\n", item.Count, item.Name)
	}
	writer.Flush()
}
