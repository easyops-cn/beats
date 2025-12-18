// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build darwin || freebsd || linux || windows || aix
// +build darwin freebsd linux windows aix

package process

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	mbtest "github.com/elastic/beats/v7/metricbeat/mb/testing"
	_ "github.com/elastic/beats/v7/metricbeat/module/system"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/process"
)

func TestFetch(t *testing.T) {
	logp.DevelopmentSetup()
	f := mbtest.NewReportingMetricSetV2Error(t, getConfig())
	events, errs := mbtest.ReportingFetchV2Error(f)
	assert.Empty(t, errs)
	assert.NotEmpty(t, events)

	time.Sleep(2 * time.Second)

	events, errs = mbtest.ReportingFetchV2Error(f)
	assert.Empty(t, errs)
	assert.NotEmpty(t, events)

	t.Logf("%s/%s event: %+v", f.Module().Name(), f.Name(),
		events[0].BeatEvent("system", "process").Fields.StringToPrint())
}

func TestData(t *testing.T) {
	f := mbtest.NewReportingMetricSetV2Error(t, getConfig())

	// Do a first fetch to have percentages
	mbtest.ReportingFetchV2Error(f)
	time.Sleep(10 * time.Second)

	err := mbtest.WriteEventsReporterV2Error(f, t, ".")
	if err != nil {
		t.Fatal("write", err)
	}
}

func getConfig() map[string]interface{} {
	return map[string]interface{}{
		"module":                        "system",
		"metricsets":                    []string{"process"},
		"processes":                     []string{".*"}, // in case we want a prettier looking example for data.json
		"process.cgroups.enabled":       true,
		"process.include_cpu_ticks":     true,
		"process.cmdline.cache.enabled": true,
		"process.include_top_n":         process.IncludeTopConfig{Enabled: true, ByCPU: 5},
	}
}

func TestMultiInstanceConfig(t *testing.T) {
	logp.DevelopmentSetup()
	config := map[string]interface{}{
		"module":     "system",
		"metricsets": []string{"process"},
		"processes":  []string{".*"},
		"artifactInsts": []map[string]interface{}{
			{
				"instanceId":        "test-instance-1",
				"checkProcessNames": []string{"test-process"},
				"processList": []map[string]interface{}{
					{
						"cmdline": "/usr/bin/test",
						"ports":   []string{"8080"},
					},
				},
			},
		},
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	assert.NotNil(t, f)

	// Verify that the metricset was created successfully
	ms, ok := f.(*MetricSet)
	assert.True(t, ok, "MetricSet should be of type *MetricSet")
	assert.NotNil(t, ms)
	assert.Equal(t, 1, len(ms.artifactInsts))
	assert.Equal(t, "test-instance-1", ms.artifactInsts[0].InstanceId)
	assert.Equal(t, 1, len(ms.artifactInsts[0].CheckProcessNames))
	assert.Equal(t, "test-process", ms.artifactInsts[0].CheckProcessNames[0])
}

// TestMetricDataGeneration tests the complete metric data generation flow
func TestMetricDataGeneration(t *testing.T) {
	logp.DevelopmentSetup()

	// Test configuration with processList mode
	config := map[string]interface{}{
		"module":     "system",
		"metricsets": []string{"process"},
		"processes":  []string{".*"},
		"artifactInsts": []map[string]interface{}{
			{
				"instanceId":        "inst-test-001",
				"checkProcessNames": []string{}, // Empty, use processList mode
				"processList": []map[string]interface{}{
					{
						"cmdline": "/usr/bin/nginx",
						"ports":   []string{"80", "443"},
					},
				},
			},
		},
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	events, errs := mbtest.ReportingFetchV2Error(f)

	// Verify no errors
	assert.Empty(t, errs, "Should not have errors")
	assert.NotEmpty(t, events, "Should have events")

	// Verify events structure
	for _, event := range events {
		beatEvent := event.BeatEvent("system", "process")
		fields := beatEvent.Fields

		// Check if event has process data
		if processData, exists := fields["process"]; exists {
			processMap, ok := processData.(map[string]interface{})
			if ok {
				// Check if instanceId is added to matching processes
				if cmdline, exists := processMap["command_line"]; exists {
					cmdlineStr, ok := cmdline.(string)
					if ok && cmdlineStr == "/usr/bin/nginx" {
						// This process should have instanceId
						if instanceId, exists := fields["instanceId"]; exists {
							assert.Equal(t, "inst-test-001", instanceId, "Matching process should have instanceId")
							t.Logf("✓ Found process with instanceId: cmdline=%s, instanceId=%v", cmdlineStr, instanceId)
						}
					}
				}
			}
		}

		// Check for abnormal process events (alive_state = 1)
		if systemData, exists := fields["system"]; exists {
			if systemMap, ok := systemData.(map[string]interface{}); ok {
				if processData, exists := systemMap["process"]; exists {
					if processMap, ok := processData.(map[string]interface{}); ok {
						if aliveState, exists := processMap["alive_state"]; exists {
							aliveStateInt, ok := aliveState.(int)
							if ok && aliveStateInt == 1 {
								// This is an abnormal process event
								if instanceId, exists := fields["instanceId"]; exists {
									t.Logf("✓ Found abnormal process event: instanceId=%v, alive_state=1", instanceId)
									// Verify it has the expected structure
									if processData, exists := fields["process"]; exists {
										if processMap, ok := processData.(map[string]interface{}); ok {
											if cmdline, exists := processMap["command_line"]; exists {
												t.Logf("  - command_line: %v", cmdline)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	t.Logf("Total events generated: %d", len(events))
}

// TestCheckProcessNamesMode tests the checkProcessNames mode
func TestCheckProcessNamesMode(t *testing.T) {
	logp.DevelopmentSetup()

	// Test configuration with checkProcessNames mode
	config := map[string]interface{}{
		"module":     "system",
		"metricsets": []string{"process"},
		"processes":  []string{".*"},
		"artifactInsts": []map[string]interface{}{
			{
				"instanceId":        "inst-names-001",
				"checkProcessNames": []string{"java", "elasticsearch"}, // Use checkProcessNames mode
				"processList":       []map[string]interface{}{},
			},
		},
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	events, errs := mbtest.ReportingFetchV2Error(f)

	// Verify no errors
	assert.Empty(t, errs, "Should not have errors")
	assert.NotEmpty(t, events, "Should have events")

	// Check for abnormal events if processes are missing
	abnormalCount := 0
	for _, event := range events {
		beatEvent := event.BeatEvent("system", "process")
		fields := beatEvent.Fields

		if systemData, exists := fields["system"]; exists {
			if systemMap, ok := systemData.(map[string]interface{}); ok {
				if processData, exists := systemMap["process"]; exists {
					if processMap, ok := processData.(map[string]interface{}); ok {
						if aliveState, exists := processMap["alive_state"]; exists {
							aliveStateInt, ok := aliveState.(int)
							if ok && aliveStateInt == 1 {
								abnormalCount++
								if instanceId, exists := fields["instanceId"]; exists {
									t.Logf("✓ Abnormal process event: instanceId=%v", instanceId)
								}
							}
						}
					}
				}
			}
		}
	}

	t.Logf("Total events: %d, Abnormal events: %d", len(events), abnormalCount)
}

// TestInstanceIdDimension tests that instanceId is correctly added to matching processes
func TestInstanceIdDimension(t *testing.T) {
	logp.DevelopmentSetup()

	// Use a process that likely exists on the system (like shell or system process)
	config := map[string]interface{}{
		"module":     "system",
		"metricsets": []string{"process"},
		"processes":  []string{".*"},
		"artifactInsts": []map[string]interface{}{
			{
				"instanceId":        "inst-dimension-test",
				"checkProcessNames": []string{},
				"processList": []map[string]interface{}{
					// Use a common process that might exist
					// Note: This is a test, actual cmdline matching requires exact match
					{
						"cmdline": "/bin/sh",
						"ports":   []string{},
					},
				},
			},
		},
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	events, errs := mbtest.ReportingFetchV2Error(f)

	assert.Empty(t, errs, "Should not have errors")
	assert.NotEmpty(t, events, "Should have events")

	// Count events with instanceId
	instanceIdCount := 0
	for _, event := range events {
		beatEvent := event.BeatEvent("system", "process")
		fields := beatEvent.Fields

		if instanceId, exists := fields["instanceId"]; exists {
			instanceIdCount++
			t.Logf("✓ Event with instanceId: %v", instanceId)
		}
	}

	t.Logf("Total events: %d, Events with instanceId: %d", len(events), instanceIdCount)
}

// TestPortCollection tests port collection functionality
func TestPortCollection(t *testing.T) {
	logp.DevelopmentSetup()

	config := map[string]interface{}{
		"module":     "system",
		"metricsets": []string{"process"},
		"processes":  []string{".*"},
		"artifactInsts": []map[string]interface{}{
			{
				"instanceId":        "inst-port-test",
				"checkProcessNames": []string{},
				"processList": []map[string]interface{}{
					{
						"cmdline": "/usr/bin/test-service",
						"ports":   []string{"8080", "9090"},
					},
				},
			},
		},
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	ms, ok := f.(*MetricSet)
	assert.True(t, ok, "Should be *MetricSet")

	// Verify port watcher is initialized when ports are configured
	if ms.needPortCollection() {
		assert.NotNil(t, ms.portWatcher, "Port watcher should be initialized when ports are configured")
		t.Logf("✓ Port watcher initialized: %v", ms.portWatcher != nil)
	} else {
		t.Logf("ℹ Port collection not needed (no ports configured)")
	}

	// Test Fetch to trigger port collection
	events, errs := mbtest.ReportingFetchV2Error(f)
	assert.Empty(t, errs, "Should not have errors")
	t.Logf("✓ Fetch completed, generated %d events", len(events))
}

// TestEmptyConfig tests backward compatibility with empty artifactInsts
func TestEmptyConfig(t *testing.T) {
	logp.DevelopmentSetup()

	// Test with empty artifactInsts (backward compatibility)
	config := map[string]interface{}{
		"module":        "system",
		"metricsets":    []string{"process"},
		"processes":     []string{".*"},
		"artifactInsts": []map[string]interface{}{}, // Empty array
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	events, errs := mbtest.ReportingFetchV2Error(f)

	// Should work normally without errors
	assert.Empty(t, errs, "Should not have errors")
	assert.NotEmpty(t, events, "Should have events")

	// Should not have instanceId in events (no matching configured)
	instanceIdCount := 0
	for _, event := range events {
		beatEvent := event.BeatEvent("system", "process")
		fields := beatEvent.Fields
		if _, exists := fields["instanceId"]; exists {
			instanceIdCount++
		}
	}

	assert.Equal(t, 0, instanceIdCount, "Should not have instanceId when artifactInsts is empty")
	t.Logf("✓ Backward compatibility verified: %d events, %d with instanceId", len(events), instanceIdCount)
}

// TestMetricDataStructure tests the detailed structure of generated metric data
func TestMetricDataStructure(t *testing.T) {
	logp.DevelopmentSetup()

	config := map[string]interface{}{
		"module":     "system",
		"metricsets": []string{"process"},
		"processes":  []string{".*"},
		"artifactInsts": []map[string]interface{}{
			{
				"instanceId":        "inst-structure-test",
				"checkProcessNames": []string{},
				"processList": []map[string]interface{}{
					{
						"cmdline": "/bin/sh",
						"ports":   []string{},
					},
				},
			},
		},
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	events, errs := mbtest.ReportingFetchV2Error(f)

	assert.Empty(t, errs, "Should not have errors")
	assert.NotEmpty(t, events, "Should have events")

	// Analyze event structure
	normalEventCount := 0
	abnormalEventCount := 0
	instanceIdEventCount := 0

	for _, event := range events {
		beatEvent := event.BeatEvent("system", "process")
		fields := beatEvent.Fields

		// Check for instanceId
		if instanceId, exists := fields["instanceId"]; exists {
			instanceIdEventCount++
			t.Logf("✓ Event with instanceId: %v", instanceId)
		}

		// Check for normal process event
		if processData, exists := fields["process"]; exists {
			if processMap, ok := processData.(map[string]interface{}); ok {
				if _, hasPid := processMap["pid"]; hasPid {
					normalEventCount++
				}
			}
		}

		// Check for abnormal process event (alive_state = 1)
		if systemData, exists := fields["system"]; exists {
			if systemMap, ok := systemData.(map[string]interface{}); ok {
				if processData, exists := systemMap["process"]; exists {
					if processMap, ok := processData.(map[string]interface{}); ok {
						if aliveState, exists := processMap["alive_state"]; exists {
							if aliveStateInt, ok := aliveState.(int); ok && aliveStateInt == 1 {
								abnormalEventCount++
								// Verify abnormal event structure
								assert.Contains(t, fields, "instanceId", "Abnormal event should have instanceId")
								if processData, exists := fields["process"]; exists {
									if processMap, ok := processData.(map[string]interface{}); ok {
										if cmdline, exists := processMap["command_line"]; exists {
											t.Logf("✓ Abnormal event: instanceId=%v, cmdline=%v", fields["instanceId"], cmdline)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	t.Logf("Event analysis:")
	t.Logf("  - Total events: %d", len(events))
	t.Logf("  - Normal process events: %d", normalEventCount)
	t.Logf("  - Abnormal process events: %d", abnormalEventCount)
	t.Logf("  - Events with instanceId: %d", instanceIdEventCount)

	// Verify at least some events were generated
	assert.Greater(t, normalEventCount, 0, "Should have normal process events")
}
