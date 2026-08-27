package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}

func runMain(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("wafcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		planPath  = flags.String("plan", "", "JSON test plan (uses the built-in plan when omitted)")
		target    = flags.String("target", "", "base HTTP(S) URL; overrides plan target")
		path      = flags.String("path", "/", "path used by the built-in plan")
		output    = flags.String("output", "", "write the machine-readable JSON report to this file")
		format    = flags.String("format", "text", "stdout format: text or json")
		parallel  = flags.Int("parallel", 1, "maximum concurrent requests")
		timeout   = flags.Duration("timeout", 0, "override the plan request timeout")
		insecure  = flags.Bool("insecure", false, "skip TLS certificate validation")
		capture   = flags.Int64("capture-body-bytes", 0, "include at most this many response body bytes per case")
		runID     = flags.String("run-id", "", "stable run identifier (generated when omitted)")
		printPlan = flags.Bool("print-plan", false, "print the resolved plan as JSON without making requests")
	)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wafcheck -target https://example.test [-path /] [options]")
		fmt.Fprintln(stderr, "       wafcheck -plan plan.json [-target URL] [options]")
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
	if *parallel < 1 || *parallel > 64 {
		fmt.Fprintln(stderr, "-parallel must be between 1 and 64")
		return 2
	}
	if *capture < 0 || *capture > 64<<10 {
		fmt.Fprintln(stderr, "-capture-body-bytes must be between 0 and 65536")
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "-format must be text or json")
		return 2
	}

	var (
		plan    Plan
		planDir string
		err     error
	)
	if *planPath == "" {
		if *target == "" {
			flags.Usage()
			return 2
		}
		plan = builtInPlan(*target, *path)
	} else {
		plan, planDir, err = loadPlan(*planPath)
		if err != nil {
			fmt.Fprintf(stderr, "load plan: %v\n", err)
			return 2
		}
		if *target != "" {
			plan.Target = *target
		}
	}
	applyPlanDefaults(&plan)
	if err := validatePlan(plan); err != nil {
		fmt.Fprintf(stderr, "invalid plan: %v\n", err)
		return 2
	}
	if *printPlan {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(plan); err != nil {
			fmt.Fprintf(stderr, "write plan: %v\n", err)
			return 2
		}
		return 0
	}

	report := runPlan(context.Background(), plan, RunOptions{
		Parallel: *parallel, InsecureTLS: *insecure, CaptureBodyBytes: *capture,
		RunID: *runID, PlanDir: planDir, TimeoutOverride: *timeout,
	})
	data, err := marshalReport(report)
	if err != nil {
		fmt.Fprintf(stderr, "encode report: %v\n", err)
		return 2
	}
	if *output != "" {
		if err := os.WriteFile(*output, append(data, '\n'), 0o600); err != nil {
			fmt.Fprintf(stderr, "write report: %v\n", err)
			return 2
		}
	}
	if *format == "json" {
		if _, err := stdout.Write(append(data, '\n')); err != nil {
			fmt.Fprintf(stderr, "write output: %v\n", err)
			return 2
		}
	} else {
		writeTextReport(stdout, report, *output)
	}
	if report.Summary.Failed != 0 {
		return 1
	}
	return 0
}

func writeTextReport(out io.Writer, report Report, outputPath string) {
	fmt.Fprintf(out, "run: %s  target: %s\n", report.RunID, report.Target)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "RESULT\tCASE\tCATEGORY\tHTTP\tDECISION\tDURATION\tREQUEST ID")
	for _, result := range report.Results {
		mark := "PASS"
		if !result.Passed {
			mark = "FAIL"
		}
		status := "-"
		if result.Status != 0 {
			status = strconv.Itoa(result.Status)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.1fms\t%s\n",
			mark, result.Name, result.Category, status, result.Decision, result.DurationMS, result.RequestID)
		for _, reason := range result.Reasons {
			fmt.Fprintf(w, "\t  %s\n", reason)
		}
		if result.Error != "" {
			fmt.Fprintf(w, "\t  error: %s\n", result.Error)
		}
	}
	w.Flush()
	fmt.Fprintf(out, "summary: %d passed, %d failed, %d request errors; elapsed %s\n",
		report.Summary.Passed, report.Summary.Failed, report.Summary.Errors,
		report.FinishedAt.Sub(report.StartedAt).Round(time.Millisecond))
	if outputPath != "" {
		fmt.Fprintf(out, "json report: %s\n", outputPath)
	}
}
