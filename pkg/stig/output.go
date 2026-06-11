package stig

import (
	"encoding/json"
	"fmt"
	"io"
)

// Color codes
const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
)

// PrintTable outputs scan results as a formatted terminal table.
func PrintTable(w io.Writer, results []Result) {
	var catIFail, catIIFail, catIIIFail int
	var pass, fail, na, errCount int

	for _, r := range results {
		switch r.Status {
		case StatusPass:
			pass++
		case StatusFail:
			fail++
			switch r.Finding.Severity {
			case "CAT I":
				catIFail++
			case "CAT II":
				catIIFail++
			case "CAT III":
				catIIIFail++
			}
		case StatusNA:
			na++
		case StatusErr:
			errCount++
		}
	}

	fmt.Fprintf(w, "\n%s%sKubeSTIG, DISA Kubernetes STIG v2r5%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "%sAuthor: Ollie Dixon%s\n", colorGray, colorReset)
	fmt.Fprintf(w, "%s══════════════════════════════════════%s\n\n", colorCyan, colorReset)

	fmt.Fprintf(w, "  %sPASS:%s  %d\n", colorGreen, colorReset, pass)
	fmt.Fprintf(w, "  %sFAIL:%s  %d\n", colorRed, colorReset, fail)
	fmt.Fprintf(w, "  %sN/A:%s   %d\n", colorGray, colorReset, na)
	if errCount > 0 {
		fmt.Fprintf(w, "  %sERROR:%s %d\n", colorYellow, colorReset, errCount)
	}
	fmt.Fprintf(w, "  ────────\n")
	fmt.Fprintf(w, "  TOTAL: %d\n\n", len(results))

	// Print failures grouped by severity
	if catIFail > 0 {
		fmt.Fprintf(w, "%s%s  CAT I FAILURES (%d), CRITICAL%s\n", colorBold, colorRed, catIFail, colorReset)
		for _, r := range results {
			if r.Status == StatusFail && r.Finding.Severity == "CAT I" {
				fmt.Fprintf(w, "  %s✗ %s%s  %s\n", colorRed, r.Finding.VID, colorReset, r.Finding.Title)
				if r.Evidence != "" {
					fmt.Fprintf(w, "    %s%s%s\n", colorGray, r.Evidence, colorReset)
				}
			}
		}
		fmt.Fprintln(w)
	}

	if catIIFail > 0 {
		fmt.Fprintf(w, "%s%s  CAT II FAILURES (%d)%s\n", colorBold, colorYellow, catIIFail, colorReset)
		for _, r := range results {
			if r.Status == StatusFail && r.Finding.Severity == "CAT II" {
				fmt.Fprintf(w, "  %s✗ %s%s  %s\n", colorYellow, r.Finding.VID, colorReset, r.Finding.Title)
				if r.Evidence != "" {
					fmt.Fprintf(w, "    %s%s%s\n", colorGray, r.Evidence, colorReset)
				}
			}
		}
		fmt.Fprintln(w)
	}

	if catIIIFail > 0 {
		fmt.Fprintf(w, "  CAT III FAILURES (%d)\n", catIIIFail)
		for _, r := range results {
			if r.Status == StatusFail && r.Finding.Severity == "CAT III" {
				fmt.Fprintf(w, "  %s✗ %s%s  %s\n", colorGray, r.Finding.VID, colorReset, r.Finding.Title)
			}
		}
		fmt.Fprintln(w)
	}

	// Summary line
	if fail == 0 {
		fmt.Fprintf(w, "  %s✓ Cluster is STIG compliant.%s\n\n", colorGreen, colorReset)
	} else {
		fmt.Fprintf(w, "  %s✗ %d finding(s) require remediation.%s\n", colorRed, fail, colorReset)
		fmt.Fprintf(w, "  %sExport CKL for STIG Viewer:  kubestig scan --output ckl > results.ckl%s\n\n", colorGray, colorReset)
	}
}

// PrintJSON outputs scan results as JSON.
func PrintJSON(w io.Writer, results []Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
