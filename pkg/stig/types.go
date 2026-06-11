package stig

// Status represents the compliance status of a finding.
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusNA   Status = "N/A"
	StatusErr  Status = "ERROR"
)

// CheckType indicates how the finding is verified.
type CheckType string

const (
	CheckClusterAPI  CheckType = "cluster_api"  // Checked via Kubernetes API
	CheckNodeConfig  CheckType = "node_config"  // Checked via node-level inspection
	CheckWorkload    CheckType = "workload"     // Checked against deployed workloads
	CheckManual      CheckType = "manual"       // Requires manual verification
)

// Finding represents a single DISA STIG finding definition.
type Finding struct {
	VID          string    `yaml:"vid" json:"vid"`
	CNTRID       string    `yaml:"cntr_id" json:"cntr_id"`
	Title        string    `yaml:"title" json:"title"`
	Severity     string    `yaml:"severity" json:"severity"`
	Category     string    `yaml:"category" json:"category"`
	NISTControls string    `yaml:"nist_controls" json:"nist_controls"`
	CheckType    CheckType `yaml:"check_type" json:"check_type"`
	Description  string    `yaml:"description" json:"description"`
	CheckField   string    `yaml:"check_field" json:"check_field"`
	ExpectedVal  string    `yaml:"expected_value" json:"expected_value"`
	Remediation  string    `yaml:"remediation" json:"remediation"`
}

// Result represents the outcome of checking a single finding against a cluster.
type Result struct {
	Finding  Finding `json:"finding"`
	Status   Status  `json:"status"`
	Actual   string  `json:"actual,omitempty"`
	Evidence string  `json:"evidence,omitempty"`
}
