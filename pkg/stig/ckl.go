package stig

import (
	"encoding/xml"
	"fmt"
	"io"
	"time"
)

// CKL XML structure matching DISA STIG Viewer Checklist Schema V2

type CKLChecklist struct {
	XMLName xml.Name `xml:"CHECKLIST"`
	Asset   CKLAsset `xml:"ASSET"`
	Stigs   CKLStigs `xml:"STIGS"`
}

type CKLAsset struct {
	Role          string `xml:"ROLE"`
	AssetType     string `xml:"ASSET_TYPE"`
	Marking       string `xml:"MARKING"`
	HostName      string `xml:"HOST_NAME"`
	HostIP        string `xml:"HOST_IP"`
	HostMAC       string `xml:"HOST_MAC"`
	HostFQDN      string `xml:"HOST_FQDN"`
	TargetComment string `xml:"TARGET_COMMENT"`
	TechArea      string `xml:"TECH_AREA"`
	TargetKey     string `xml:"TARGET_KEY"`
	WebOrDatabase string `xml:"WEB_OR_DATABASE"`
	WebDBSite     string `xml:"WEB_DB_SITE"`
	WebDBInstance  string `xml:"WEB_DB_INSTANCE"`
}

type CKLStigs struct {
	ISTIG CKLiSTIG `xml:"iSTIG"`
}

type CKLiSTIG struct {
	STIGInfo CKLSTIGInfo `xml:"STIG_INFO"`
	Vulns    []CKLVuln   `xml:"VULN"`
}

type CKLSTIGInfo struct {
	SIData []CKLSIData `xml:"SI_DATA"`
}

type CKLSIData struct {
	SIDName string `xml:"SID_NAME"`
	SIDData string `xml:"SID_DATA"`
}

type CKLVuln struct {
	STIGData             []CKLSTIGData `xml:"STIG_DATA"`
	Status               string        `xml:"STATUS"`
	FindingDetails       string        `xml:"FINDING_DETAILS"`
	Comments             string        `xml:"COMMENTS"`
	SeverityOverride     string        `xml:"SEVERITY_OVERRIDE"`
	SeverityJustification string       `xml:"SEVERITY_JUSTIFICATION"`
}

type CKLSTIGData struct {
	VulnAttribute string `xml:"VULN_ATTRIBUTE"`
	AttributeData string `xml:"ATTRIBUTE_DATA"`
}

// statusToCKL converts KubeSTIG status to CKL status values
func statusToCKL(s Status) string {
	switch s {
	case StatusPass:
		return "NotAFinding"
	case StatusFail:
		return "Open"
	case StatusNA:
		return "Not_Applicable"
	default:
		return "Not_Reviewed"
	}
}

// severityToCKL converts KubeSTIG severity to CKL severity
func severityToCKL(sev string) string {
	switch sev {
	case "CAT I":
		return "high"
	case "CAT II":
		return "medium"
	case "CAT III":
		return "low"
	default:
		return "medium"
	}
}

// GenerateCKL creates a STIG Viewer compatible CKL file from scan results.
func GenerateCKL(w io.Writer, results []Result, hostname, hostIP string) error {
	checklist := CKLChecklist{
		Asset: CKLAsset{
			Role:          "None",
			AssetType:     "Computing",
			Marking:       "",
			HostName:      hostname,
			HostIP:        hostIP,
			HostMAC:       "",
			HostFQDN:      hostname,
			TargetComment: fmt.Sprintf("Scanned by KubeSTIG v0.1.0 (Author: Ollie Dixon) on %s", time.Now().Format("2006-01-02 15:04:05")),
			TechArea:      "Other Review",
			TargetKey:     "4082",
			WebOrDatabase: "false",
			WebDBSite:     "",
			WebDBInstance:  "",
		},
		Stigs: CKLStigs{
			ISTIG: CKLiSTIG{
				STIGInfo: CKLSTIGInfo{
					SIData: []CKLSIData{
						{SIDName: "version", SIDData: "2"},
						{SIDName: "classification", SIDData: "UNCLASSIFIED"},
						{SIDName: "customname", SIDData: ""},
						{SIDName: "stigid", SIDData: "Kubernetes_STIG"},
						{SIDName: "description", SIDData: "Kubernetes Security Technical Implementation Guide"},
						{SIDName: "filename", SIDData: "U_Kubernetes_STIG_V2R5"},
						{SIDName: "releaseinfo", SIDData: "Release: 5 Benchmark Date: 31 Mar 2026"},
						{SIDName: "title", SIDData: "Kubernetes Security Technical Implementation Guide"},
						{SIDName: "uuid", SIDData: "kubestig-scan-" + time.Now().Format("20060102-150405")},
						{SIDName: "notice", SIDData: "terms-of-use"},
						{SIDName: "source", SIDData: "KubeSTIG by Ollie Dixon"},
					},
				},
			},
		},
	}

	// Convert each result to a CKL VULN entry
	for _, r := range results {
		vuln := CKLVuln{
			Status:               statusToCKL(r.Status),
			FindingDetails:       r.Evidence,
			Comments:             fmt.Sprintf("Automated scan by KubeSTIG. Actual value: %s", r.Actual),
			SeverityOverride:     "",
			SeverityJustification: "",
			STIGData: []CKLSTIGData{
				{VulnAttribute: "Vuln_Num", AttributeData: r.Finding.VID},
				{VulnAttribute: "Severity", AttributeData: severityToCKL(r.Finding.Severity)},
				{VulnAttribute: "Group_Title", AttributeData: r.Finding.CNTRID},
				{VulnAttribute: "Rule_ID", AttributeData: r.Finding.CNTRID + "_rule"},
				{VulnAttribute: "Rule_Ver", AttributeData: r.Finding.CNTRID},
				{VulnAttribute: "Rule_Title", AttributeData: r.Finding.Title},
				{VulnAttribute: "Vuln_Discuss", AttributeData: r.Finding.Description},
				{VulnAttribute: "IA_Controls", AttributeData: ""},
				{VulnAttribute: "Check_Content", AttributeData: r.Finding.Description},
				{VulnAttribute: "Fix_Text", AttributeData: r.Finding.Remediation},
				{VulnAttribute: "False_Positives", AttributeData: ""},
				{VulnAttribute: "False_Negatives", AttributeData: ""},
				{VulnAttribute: "Documentable", AttributeData: "false"},
				{VulnAttribute: "Mitigations", AttributeData: ""},
				{VulnAttribute: "Potential_Impact", AttributeData: ""},
				{VulnAttribute: "Third_Party_Tools", AttributeData: "KubeSTIG by Ollie Dixon"},
				{VulnAttribute: "Mitigation_Control", AttributeData: ""},
				{VulnAttribute: "Responsibility", AttributeData: ""},
				{VulnAttribute: "Security_Override_Guidance", AttributeData: ""},
				{VulnAttribute: "STIGRef", AttributeData: "Kubernetes STIG V2R5"},
				{VulnAttribute: "CCI_REF", AttributeData: r.Finding.NISTControls},
				{VulnAttribute: "Class", AttributeData: "Unclass"},
				{VulnAttribute: "Weight", AttributeData: "10.0"},
				{VulnAttribute: "TargetKey", AttributeData: "4082"},
			},
		}
		checklist.Stigs.ISTIG.Vulns = append(checklist.Stigs.ISTIG.Vulns, vuln)
	}

	// Write XML header
	fmt.Fprint(w, xml.Header)

	// Write the CKL XML
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(checklist)
}
