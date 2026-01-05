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
	"github.com/elastic/elastic-agent-libs/mapstr"
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
				"instanceId": "test-instance-1",
				"processMatchGroups": []map[string]interface{}{
					{"keywords": []string{"test-process"}},
				},
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
	assert.Equal(t, 1, len(ms.artifactInsts[0].ProcessMatchGroups))
	assert.Equal(t, "test-process", ms.artifactInsts[0].ProcessMatchGroups[0].Keywords[0])
}

// TestProcessMatchGroupsWithSamePort tests the scenario where two instances
// have different ProcessMatchGroups but same port, and cmdline changes
func TestProcessMatchGroupsWithSamePort(t *testing.T) {
	logp.DevelopmentSetup()

	// Configuration: two instances with same port but different keywords
	config := map[string]interface{}{
		"module":     "system",
		"metricsets": []string{"process"},
		"processes":  []string{".*"},
		"artifactInsts": []map[string]interface{}{
			{
				"instanceId": "inst-kafka-broker",
				"processMatchGroups": []map[string]interface{}{
					{"keywords": []string{"kafka", "broker"}},
				},
				"processList": []map[string]interface{}{
					{
						"cmdline": "/usr/bin/kafka-server-old", // cmdline may change
						"ports":   []string{"9092"},
					},
				},
			},
			{
				"instanceId": "inst-kafka-zookeeper",
				"processMatchGroups": []map[string]interface{}{
					{"keywords": []string{"kafka", "zookeeper"}},
				},
				"processList": []map[string]interface{}{
					{
						"cmdline": "/usr/bin/kafka-zookeeper-old", // cmdline may change
						"ports":   []string{"9092"},               // Same port
					},
				},
			},
		},
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	ms, ok := f.(*MetricSet)
	assert.True(t, ok, "Should be *MetricSet")
	assert.NotNil(t, ms)

	// Test 1: Verify index building
	t.Run("IndexBuilding", func(t *testing.T) {
		// Verify both instances are indexed
		assert.Equal(t, 2, len(ms.artifactInsts))

		// Verify port 9092 maps to both instances
		instIds9092 := ms.portToInstId["9092"]
		assert.NotNil(t, instIds9092, "Port 9092 should have instance IDs")
		assert.Equal(t, 2, len(instIds9092), "Port 9092 should map to 2 instance IDs")

		t.Logf("✓ Index building verified:")
		t.Logf("  - Port 9092 maps to: %v", instIds9092)
	})

	// Test 2: Verify ProcessMatchGroups matching with changed cmdline
	t.Run("ProcessMatchGroupsMatching", func(t *testing.T) {
		// Simulate process with changed cmdline but matching keywords
		// Process 1: cmdline changed but contains "kafka" and "broker"
		procInfo1 := ProcessInfo{
			Cmdline:     "/opt/kafka/bin/kafka-server-new --broker-id=1",
			ProcessName: "java",
		}

		instanceId1 := ms.findInstanceIdByProcessMatchGroups(procInfo1)
		assert.Equal(t, "inst-kafka-broker", instanceId1, "Should match inst-kafka-broker")

		// Process 2: cmdline changed but contains "kafka" and "zookeeper"
		procInfo2 := ProcessInfo{
			Cmdline:     "/opt/kafka/bin/kafka-zookeeper-new --zk-port=2181",
			ProcessName: "java",
		}

		instanceId2 := ms.findInstanceIdByProcessMatchGroups(procInfo2)
		assert.Equal(t, "inst-kafka-zookeeper", instanceId2, "Should match inst-kafka-zookeeper")

		// Process 3: cmdline changed but only contains "kafka" (should not match)
		procInfo3 := ProcessInfo{
			Cmdline:     "/opt/kafka/bin/kafka-client",
			ProcessName: "java",
		}

		instanceId3 := ms.findInstanceIdByProcessMatchGroups(procInfo3)
		assert.Empty(t, instanceId3, "Should not match any instance (missing keywords)")

		t.Logf("✓ ProcessMatchGroups matching verified:")
		t.Logf("  - Process 1 (kafka+broker): matched %s", instanceId1)
		t.Logf("  - Process 2 (kafka+zookeeper): matched %s", instanceId2)
		t.Logf("  - Process 3 (kafka only): matched %s (expected empty)", instanceId3)
	})

	// Test 3: Verify matching with processName
	t.Run("ProcessMatchGroupsWithProcessName", func(t *testing.T) {
		// Process with keywords in processName instead of cmdline
		procInfo1 := ProcessInfo{
			Cmdline:     "/usr/bin/java -jar app.jar",
			ProcessName: "kafka-broker-server",
		}

		instanceId1 := ms.findInstanceIdByProcessMatchGroups(procInfo1)
		assert.Equal(t, "inst-kafka-broker", instanceId1, "Should match via processName")

		procInfo2 := ProcessInfo{
			Cmdline:     "/usr/bin/java -jar app.jar",
			ProcessName: "kafka-zookeeper-server",
		}

		instanceId2 := ms.findInstanceIdByProcessMatchGroups(procInfo2)
		assert.Equal(t, "inst-kafka-zookeeper", instanceId2, "Should match via processName")

		t.Logf("✓ ProcessMatchGroups with processName verified:")
		t.Logf("  - Process 1 (processName contains kafka+broker): matched %s", instanceId1)
		t.Logf("  - Process 2 (processName contains kafka+zookeeper): matched %s", instanceId2)
	})

	// Test 4: Verify fallback to port matching when ProcessMatchGroups fails
	t.Run("FallbackToPortMatching", func(t *testing.T) {
		// Mock pidToPorts to simulate a process listening on port 9092
		ms.pidToPorts = map[int][]string{
			12345: {"9092"},
		}

		// Create mock root with PID and cmdline that doesn't match keywords
		root := mapstr.M{
			"process.pid":          12345,
			"process.command_line": "/usr/bin/unknown-process",
			"process.name":         "unknown",
		}

		// Test addInstanceIdDimension logic
		procs := []mapstr.M{
			{
				"cpu": mapstr.M{"pct": 0.5},
			},
		}
		roots := []mapstr.M{root}

		// Call addInstanceIdDimension
		ms.addInstanceIdDimension(procs, roots)

		// Since ProcessMatchGroups won't match, it should fallback to port matching
		// Port 9092 matches both instances, so _matched_instance_ids should be set
		matchedInstIdsVal, hasMultiple := procs[0]["_matched_instance_ids"]
		assert.True(t, hasMultiple, "Should have _matched_instance_ids when port matches multiple instances")

		matchedInstIds, ok := matchedInstIdsVal.([]string)
		assert.True(t, ok, "Should be []string type")
		assert.Equal(t, 2, len(matchedInstIds), "Should match both instances via port")

		t.Logf("✓ Fallback to port matching verified:")
		t.Logf("  - Process with unmatched cmdline but port 9092")
		t.Logf("  - Matched instance IDs via port: %v", matchedInstIds)
	})

	// Test 5: Verify priority: ProcessMatchGroups > Port matching
	t.Run("PriorityOrder", func(t *testing.T) {
		// Mock pidToPorts
		ms.pidToPorts = map[int][]string{
			99999: {"9092"},
		}

		// Process with matching keywords (should use ProcessMatchGroups, not port)
		root := mapstr.M{
			"process.pid":          99999,
			"process.command_line": "/opt/kafka/bin/kafka-server-new --broker-id=1",
			"process.name":         "java",
		}

		procs := []mapstr.M{
			{
				"cpu": mapstr.M{"pct": 0.7},
			},
		}
		roots := []mapstr.M{root}

		ms.addInstanceIdDimension(procs, roots)

		// Should match via ProcessMatchGroups, not port
		instanceId, exists := procs[0]["instanceId"]
		assert.True(t, exists, "Should have instanceId")
		assert.Equal(t, "inst-kafka-broker", instanceId, "Should match via ProcessMatchGroups, not port")

		// Should not have _matched_instance_ids (port matching not reached)
		_, hasMultiple := procs[0]["_matched_instance_ids"]
		assert.False(t, hasMultiple, "Should not have _matched_instance_ids when ProcessMatchGroups matches")

		t.Logf("✓ Priority order verified:")
		t.Logf("  - Process with matching keywords: matched %s via ProcessMatchGroups", instanceId)
		t.Logf("  - Port matching was not used (correct priority)")
	})

	// Test 6: Verify ProcessMatchGroups with workingDirectory
	t.Run("ProcessMatchGroupsWithWorkingDirectory", func(t *testing.T) {
		// Process with keywords in workingDirectory
		procInfo1 := ProcessInfo{
			Cmdline:          "/usr/bin/java -jar app.jar",
			ProcessName:      "java",
			WorkingDirectory: "/opt/kafka/broker",
		}

		instanceId1 := ms.findInstanceIdByProcessMatchGroups(procInfo1)
		assert.Equal(t, "inst-kafka-broker", instanceId1, "Should match via workingDirectory")

		procInfo2 := ProcessInfo{
			Cmdline:          "/usr/bin/java -jar app.jar",
			ProcessName:      "java",
			WorkingDirectory: "/opt/kafka/zookeeper",
		}

		instanceId2 := ms.findInstanceIdByProcessMatchGroups(procInfo2)
		assert.Equal(t, "inst-kafka-zookeeper", instanceId2, "Should match via workingDirectory")

		t.Logf("✓ ProcessMatchGroups with workingDirectory verified:")
		t.Logf("  - Process 1 (workingDirectory contains kafka+broker): matched %s", instanceId1)
		t.Logf("  - Process 2 (workingDirectory contains kafka+zookeeper): matched %s", instanceId2)
	})
}

// TestPortMatchingAllPortsRequired tests the port matching logic where ALL ports must match
func TestPortMatchingAllPortsRequired(t *testing.T) {
	logp.DevelopmentSetup()

	// Configuration: two instances with different port configurations
	config := map[string]interface{}{
		"module":     "system",
		"metricsets": []string{"process"},
		"processes":  []string{".*"},
		"artifactInsts": []map[string]interface{}{
			{
				"instanceId": "inst-nginx-1",
				"processList": []map[string]interface{}{
					{
						"cmdline": "C:\\hifar\\nginx\\nginx.exe",
						"ports":   []string{"6001", "6002"},
					},
				},
			},
			{
				"instanceId": "inst-nginx-2",
				"processList": []map[string]interface{}{
					{
						"cmdline": "C:\\hifar\\nginx\\nginx.exe",
						"ports":   []string{"6001"},
					},
				},
			},
		},
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	ms, ok := f.(*MetricSet)
	assert.True(t, ok, "Should be *MetricSet")
	assert.NotNil(t, ms)

	// Test 1: Process with all ports matching instance 1
	t.Run("AllPortsMatchInstance1", func(t *testing.T) {
		ms.pidToPorts = map[int][]string{
			1001: {"6001", "6002"},
		}

		// Use different cmdline to avoid exact cmdline match
		root := mapstr.M{
			"process.pid":          1001,
			"process.command_line": "C:\\hifar\\nginx\\nginx-new.exe",
		}

		procs := []mapstr.M{{"cpu": mapstr.M{"pct": 0.5}}}
		roots := []mapstr.M{root}

		ms.addInstanceIdDimension(procs, roots)

		// Should match instance 1 (all ports: 6001, 6002 match)
		instanceId, exists := procs[0]["instanceId"]
		assert.True(t, exists, "Should have instanceId")
		assert.Equal(t, "inst-nginx-1", instanceId, "Should match inst-nginx-1 (all ports match)")

		t.Logf("✓ All ports match instance 1 verified")
	})

	// Test 2: Process with only one port (should not match instance 1, but match instance 2)
	t.Run("PartialPortsMatch", func(t *testing.T) {
		ms.pidToPorts = map[int][]string{
			1002: {"6001"},
		}

		// Use different cmdline to avoid exact cmdline match
		root := mapstr.M{
			"process.pid":          1002,
			"process.command_line": "C:\\hifar\\nginx\\nginx-new.exe",
		}

		procs := []mapstr.M{{"cpu": mapstr.M{"pct": 0.5}}}
		roots := []mapstr.M{root}

		ms.addInstanceIdDimension(procs, roots)

		// Should match instance 2 (only port 6001 matches, which is sufficient for instance 2)
		instanceId, exists := procs[0]["instanceId"]
		assert.True(t, exists, "Should have instanceId")
		assert.Equal(t, "inst-nginx-2", instanceId, "Should match inst-nginx-2 (port 6001 matches)")

		t.Logf("✓ Partial ports match verified")
	})

	// Test 3: Process with extra port (should not match any instance)
	t.Run("ExtraPortNotMatching", func(t *testing.T) {
		ms.pidToPorts = map[int][]string{
			1003: {"6001", "6002", "6003"},
		}

		// Use different cmdline to avoid exact cmdline match
		root := mapstr.M{
			"process.pid":          1003,
			"process.command_line": "C:\\hifar\\nginx\\nginx-new.exe",
		}

		procs := []mapstr.M{{"cpu": mapstr.M{"pct": 0.5}}}
		roots := []mapstr.M{root}

		ms.addInstanceIdDimension(procs, roots)

		// Should not match instance 1 (has extra port 6003)
		// Should not match instance 2 (has extra ports 6002, 6003)
		instanceId, exists := procs[0]["instanceId"]
		if exists {
			assert.Empty(t, instanceId, "Should not match any instance (has extra ports)")
		}

		t.Logf("✓ Extra port not matching verified")
	})

	// Test 4: Process with multiple ports matching multiple instances
	t.Run("MultipleInstancesMatch", func(t *testing.T) {
		// Create a new config where both instances share port 6001
		config2 := map[string]interface{}{
			"module":     "system",
			"metricsets": []string{"process"},
			"processes":  []string{".*"},
			"artifactInsts": []map[string]interface{}{
				{
					"instanceId": "inst-app-1",
					"processList": []map[string]interface{}{
						{
							"cmdline": "/usr/bin/app",
							"ports":   []string{"6001", "6002"},
						},
					},
				},
				{
					"instanceId": "inst-app-2",
					"processList": []map[string]interface{}{
						{
							"cmdline": "/usr/bin/app",
							"ports":   []string{"6001", "6003"},
						},
					},
				},
			},
		}

		f2 := mbtest.NewReportingMetricSetV2Error(t, config2)
		ms2, ok2 := f2.(*MetricSet)
		assert.True(t, ok2)

		// Process with ports 6001, 6002 (matches instance 1)
		ms2.pidToPorts = map[int][]string{
			2001: {"6001", "6002"},
		}

		// Use different cmdline to avoid exact cmdline match
		root := mapstr.M{
			"process.pid":          2001,
			"process.command_line": "/usr/bin/app-new",
		}

		procs := []mapstr.M{{"cpu": mapstr.M{"pct": 0.5}}}
		roots := []mapstr.M{root}

		ms2.addInstanceIdDimension(procs, roots)

		// Should match only instance 1 (all ports match)
		instanceId, exists := procs[0]["instanceId"]
		assert.True(t, exists, "Should have instanceId")
		assert.Equal(t, "inst-app-1", instanceId, "Should match inst-app-1 (all ports: 6001, 6002 match)")

		t.Logf("✓ Multiple instances match verified")
	})
}

// TestDeadProcessDetection tests the dead process detection logic
func TestDeadProcessDetection(t *testing.T) {
	logp.DevelopmentSetup()

	config := map[string]interface{}{
		"module":     "system",
		"metricsets": []string{"process"},
		"processes":  []string{".*"},
		"artifactInsts": []map[string]interface{}{
			{
				"instanceId": "inst-kafka",
				"processMatchGroups": []map[string]interface{}{
					{"keywords": []string{"kafka", "broker"}},
				},
			},
			{
				"instanceId": "inst-nginx",
				"processList": []map[string]interface{}{
					{
						"cmdline": "C:\\hifar\\nginx\\nginx.exe",
						"ports":   []string{"6001", "6002"},
					},
				},
			},
		},
	}

	f := mbtest.NewReportingMetricSetV2Error(t, config)
	ms, ok := f.(*MetricSet)
	assert.True(t, ok, "Should be *MetricSet")
	assert.NotNil(t, ms)

	// Test 1: Dead process detection for ProcessMatchGroups (Branch A)
	t.Run("DeadProcessProcessMatchGroups", func(t *testing.T) {
		// No alive processes with matching keywords
		procs := []mapstr.M{
			{
				"cpu": mapstr.M{"pct": 0.5},
			},
		}
		roots := []mapstr.M{
			{
				"process.pid":          1001,
				"process.command_line": "/usr/bin/java -jar other-app.jar",
				"process.name":         "java",
			},
		}

		aliveData := ms.buildAliveProcessData(procs, roots)
		deadProcs := ms.checkInstanceAlive(ms.artifactInsts[0], aliveData)

		// Should detect dead process
		assert.Equal(t, 1, len(deadProcs), "Should detect dead process")
		assert.Equal(t, "inst-kafka", deadProcs[0].InstanceId)
		assert.Equal(t, "/kafka/broker", deadProcs[0].Identifier)

		t.Logf("✓ Dead process detection for ProcessMatchGroups verified")
	})

	// Test 2: Alive process for ProcessMatchGroups (should not report dead)
	t.Run("AliveProcessProcessMatchGroups", func(t *testing.T) {
		// Process with matching keywords
		procs := []mapstr.M{
			{
				"cpu": mapstr.M{"pct": 0.5},
			},
		}
		roots := []mapstr.M{
			{
				"process.pid":          1002,
				"process.command_line": "/opt/kafka/bin/kafka-server --broker-id=1",
				"process.name":         "java",
			},
		}

		aliveData := ms.buildAliveProcessData(procs, roots)
		deadProcs := ms.checkInstanceAlive(ms.artifactInsts[0], aliveData)

		// Should not detect dead process
		assert.Equal(t, 0, len(deadProcs), "Should not detect dead process when alive")

		t.Logf("✓ Alive process for ProcessMatchGroups verified")
	})

	// Test 3: Dead process detection for ProcessList (Branch B)
	t.Run("DeadProcessProcessList", func(t *testing.T) {
		// No alive processes with matching cmdline or ports
		procs := []mapstr.M{
			{
				"cpu": mapstr.M{"pct": 0.5},
			},
		}
		roots := []mapstr.M{
			{
				"process.pid":          1003,
				"process.command_line": "/usr/bin/other-process",
				"process.name":         "other",
			},
		}

		ms.pidToPorts = map[int][]string{
			1003: {"8080"},
		}

		aliveData := ms.buildAliveProcessData(procs, roots)
		deadProcs := ms.checkInstanceAlive(ms.artifactInsts[1], aliveData)

		// Should detect dead process (neither cmdline nor ports match)
		assert.Equal(t, 1, len(deadProcs), "Should detect dead process")
		assert.Equal(t, "inst-nginx", deadProcs[0].InstanceId)
		assert.Equal(t, "C:\\hifar\\nginx\\nginx.exe", deadProcs[0].Identifier)

		t.Logf("✓ Dead process detection for ProcessList verified")
	})

	// Test 4: Alive process for ProcessList (cmdline matches)
	t.Run("AliveProcessProcessListCmdline", func(t *testing.T) {
		// Process with matching cmdline
		procs := []mapstr.M{
			{
				"cpu": mapstr.M{"pct": 0.5},
			},
		}
		roots := []mapstr.M{
			{
				"process.pid":          1004,
				"process.command_line": "C:\\hifar\\nginx\\nginx.exe",
				"process.name":         "nginx",
			},
		}

		ms.pidToPorts = map[int][]string{}

		aliveData := ms.buildAliveProcessData(procs, roots)
		deadProcs := ms.checkInstanceAlive(ms.artifactInsts[1], aliveData)

		// Should not detect dead process (cmdline matches)
		assert.Equal(t, 0, len(deadProcs), "Should not detect dead process when cmdline matches")

		t.Logf("✓ Alive process for ProcessList (cmdline) verified")
	})

	// Test 5: Alive process for ProcessList (ports match)
	t.Run("AliveProcessProcessListPorts", func(t *testing.T) {
		// Process with matching ports
		procs := []mapstr.M{
			{
				"cpu": mapstr.M{"pct": 0.5},
			},
		}
		roots := []mapstr.M{
			{
				"process.pid":          1005,
				"process.command_line": "/usr/bin/nginx",
				"process.name":         "nginx",
			},
		}

		ms.pidToPorts = map[int][]string{
			1005: {"6001"},
		}

		aliveData := ms.buildAliveProcessData(procs, roots)
		deadProcs := ms.checkInstanceAlive(ms.artifactInsts[1], aliveData)

		// Should not detect dead process (ports match)
		assert.Equal(t, 0, len(deadProcs), "Should not detect dead process when ports match")

		t.Logf("✓ Alive process for ProcessList (ports) verified")
	})

	// Test 6: Dead process detection with workingDirectory
	t.Run("DeadProcessWithWorkingDirectory", func(t *testing.T) {
		// Process with keywords in workingDirectory
		procs := []mapstr.M{
			{
				"cpu": mapstr.M{"pct": 0.5},
			},
		}
		roots := []mapstr.M{
			{
				"process.pid":               1006,
				"process.command_line":      "/usr/bin/java -jar app.jar",
				"process.name":              "java",
				"process.working_directory": "/opt/kafka/broker",
			},
		}

		aliveData := ms.buildAliveProcessData(procs, roots)
		deadProcs := ms.checkInstanceAlive(ms.artifactInsts[0], aliveData)

		// Should not detect dead process (workingDirectory contains keywords)
		assert.Equal(t, 0, len(deadProcs), "Should not detect dead process when workingDirectory matches")

		t.Logf("✓ Dead process detection with workingDirectory verified")
	})
}
