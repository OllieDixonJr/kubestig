package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/OllieDixonJr/kubestig/pkg/scanner"
	"github.com/OllieDixonJr/kubestig/pkg/stig"
	"github.com/spf13/cobra"
)

func scanCmd() *cobra.Command {
	var kubeconfig string
	var outputFormat string
	var severity string
	var hostname string
	var hostIP string
	var insecureKubelet bool
	var withNodeAgent bool
	var agentImage string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a Kubernetes cluster against DISA STIG findings",
		Long:  "Scans the target cluster against the DISA Kubernetes STIG and reports pass/fail status. Current implementation covers a subset of the STIG; see pkg/stig/findings/ for the full list of supported V-IDs.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load STIG definitions
			defs, err := stig.LoadDefinitions()
			if err != nil {
				return fmt.Errorf("failed to load STIG definitions: %w", err)
			}

			// Create scanner
			s, err := scanner.New(kubeconfig)
			if err != nil {
				return fmt.Errorf("failed to connect to cluster: %w", err)
			}
			s.InsecureKubelet = insecureKubelet
			s.WithNodeAgent = withNodeAgent
			s.AgentImage = agentImage

			// Run scan
			results, err := s.Scan(defs)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Filter by severity if specified
			if severity != "" {
				results = filterBySeverity(results, severity)
			}

			// Output
			switch outputFormat {
			case "json":
				return stig.PrintJSON(os.Stdout, results)
			case "ckl":
				h := hostname
				if h == "" {
					h = "kubernetes-cluster"
				}
				ip := hostIP
				if ip == "" {
					ip = "0.0.0.0"
				}
				return stig.GenerateCKL(os.Stdout, results, h, ip)
			default:
				stig.PrintTable(os.Stdout, results)
			}

			// Exit non-zero if any CAT I failures
			for _, r := range results {
				if r.Status == stig.StatusFail && r.Finding.Severity == "CAT I" {
					os.Exit(1)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to ~/.kube/config)")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, ckl")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter by severity: CAT_I, CAT_II, CAT_III")
	cmd.Flags().StringVar(&hostname, "hostname", "", "Hostname for CKL output (used in STIG Viewer)")
	cmd.Flags().StringVar(&hostIP, "host-ip", "", "Host IP for CKL output (used in STIG Viewer)")
	cmd.Flags().BoolVar(&insecureKubelet, "insecure-kubelet", false, "Skip kubelet serving-cert verification when reading /configz (for clusters without serverTLSBootstrap)")
	cmd.Flags().BoolVar(&withNodeAgent, "with-node-agent", false, "Deploy an ephemeral DaemonSet to answer file-permission and process-state findings, then clean up")
	cmd.Flags().StringVar(&agentImage, "agent-image", "", "Container image for the node agent (default: docker.io/library/busybox:stable)")

	return cmd
}

func filterBySeverity(results []stig.Result, severity string) []stig.Result {
	sev := strings.ReplaceAll(strings.ToUpper(severity), "_", " ")
	var filtered []stig.Result
	for _, r := range results {
		if r.Finding.Severity == sev {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
