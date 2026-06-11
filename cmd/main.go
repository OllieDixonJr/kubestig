package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "0.1.0"
	author  = "Ollie Dixon"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "kubestig",
		Short: "KubeSTIG, DISA Kubernetes STIG v2r5 compliance scanner",
		Long: fmt.Sprintf(
			"KubeSTIG %s, DISA Kubernetes STIG v2r5 compliance scanner\n"+
				"Author: %s, Apache 2.0, github.com/kubestig/kubestig\n"+
				"Scan only. Remediation is out of scope, see STIG Fix Text in CKL output.",
			version, author,
		),
	}

	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(reportCmd())
	rootCmd.AddCommand(versionCmd())

	// Let the main loop own error printing so Cobra doesn't double-print
	// the message on RunE errors. Usage is still printed for flag/arg
	// problems (SilenceUsage left at its default), but plain failures
	// (e.g. unreachable cluster) now print exactly once.
	rootCmd.SilenceErrors = true

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print KubeSTIG version and author info",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("KubeSTIG v%s\n", version)
			fmt.Printf("Author: %s\n", author)
			fmt.Println("License: Apache 2.0")
			fmt.Println("Need help? github.com/kubestig/kubestig")
		},
	}
}
