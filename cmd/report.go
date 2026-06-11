package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func reportCmd() *cobra.Command {
	var outputFile string
	var format string

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a STIG compliance report",
		Long:  "Scans the cluster and generates an audit-ready report in PDF or text format.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: Implement PDF report generation in Phase 2
			fmt.Println("Report generation will be available in v0.2.0")
			fmt.Println("For now, use: kubestig scan --output json > report.json")
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "stig-report.pdf", "Output file path")
	cmd.Flags().StringVar(&format, "format", "pdf", "Report format: pdf, text")

	return cmd
}
