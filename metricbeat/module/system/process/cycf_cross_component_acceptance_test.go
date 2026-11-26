// Independent project acceptance harness; fixtures are rendered from the
// actual monitor-kit template by the project validation-harness module.
package process

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/metricbeat/mb"
)

func TestCYCFActualTemplateAndBeatsLoader(t *testing.T) {
	fixturePath := os.Getenv("CYCF_ACCEPTANCE_FIXTURES")
	if fixturePath == "" {
		fixturePath = filepath.Join("testdata", "cmdline_transform_fixtures.json")
	}
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read actual-template acceptance fixtures: %v", err)
	}
	var fixtures []struct {
		Name        string  `json:"name"`
		YAML        string  `json:"yaml"`
		Pattern     *string `json:"pattern"`
		Replacement string  `json:"replacement"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 22 {
		t.Fatalf("want all 22 actual-template fixtures, got %d", len(fixtures))
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metricbeat.yml")
			if err := os.WriteFile(path, []byte(fixture.YAML), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := common.LoadFile(path)
			if err != nil {
				t.Fatalf("actual common.LoadFile: %v", err)
			}
			var parsed Config
			if err := cfg.Unpack(&parsed); err != nil {
				t.Fatalf("actual process.Config unpack: %v", err)
			}
			if len(parsed.ArtifactInsts) != 1 || parsed.ArtifactInsts[0].InstanceId != "cycf-synthetic" {
				t.Fatalf("instance identity not preserved: %+v", parsed.ArtifactInsts)
			}
			transform := parsed.ArtifactInsts[0].CmdlineTransform
			if fixture.Pattern == nil {
				if transform != nil {
					t.Fatalf("unexpected transform for unconfigured instance: %+v", transform)
				}
			} else if transform == nil || transform.Pattern != *fixture.Pattern || transform.Replacement != fixture.Replacement {
				t.Fatalf("original Go rule not preserved: expected pattern=%q replacement=%q, actual=%+v", *fixture.Pattern, fixture.Replacement, transform)
			}
			_, metricsets, err := mb.NewModule(cfg, mb.Registry)
			if err != nil {
				t.Fatalf("actual module initialization: %v", err)
			}
			if len(metricsets) != 1 {
				t.Fatalf("want one initialized metricset, got %d", len(metricsets))
			}
			metricset, ok := metricsets[0].(*MetricSet)
			if !ok {
				t.Fatalf("unexpected actual metricset type %T", metricsets[0])
			}
			for _, raw := range []string{"java -jar app.jar --server.port=8080", "app --port=1234", `C:\apps\worker --name="synthetic"`, "app"} {
				want := raw
				if fixture.Pattern != nil && *fixture.Pattern != "" {
					pattern, err := regexp.Compile(*fixture.Pattern)
					if err != nil {
						t.Fatal(err)
					}
					want = pattern.ReplaceAllString(raw, fixture.Replacement)
				}
				if got := metricset.transformCmdline("cycf-synthetic", raw); got != want {
					t.Fatalf("actual initialized rule: raw=%q want=%q got=%q", raw, want, got)
				}
				if got := metricset.transformCmdline("unknown", raw); got != raw {
					t.Fatalf("unknown instance changed: raw=%q got=%q", raw, got)
				}
			}
		})
	}
}
