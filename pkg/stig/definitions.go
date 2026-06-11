package stig

import (
	"embed"
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed findings/*.yaml
var findingsFS embed.FS

// LoadDefinitions loads all finding definitions from the embedded findings/ directory.
// Each finding is a separate YAML file named by its V-ID (e.g., V-242390.yaml).
func LoadDefinitions() ([]Finding, error) {
	entries, err := findingsFS.ReadDir("findings")
	if err != nil {
		return nil, fmt.Errorf("cannot read findings directory: %w", err)
	}

	var findings []Finding
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		data, err := findingsFS.ReadFile("findings/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("cannot read %s: %w", entry.Name(), err)
		}

		var f Finding
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("invalid YAML in %s: %w", entry.Name(), err)
		}

		findings = append(findings, f)
	}

	return findings, nil
}
