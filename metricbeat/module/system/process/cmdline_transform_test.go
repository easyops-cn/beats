// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License").

//go:build darwin || freebsd || linux || windows || aix
// +build darwin freebsd linux windows aix

package process

import (
	"errors"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/metricbeat/mb"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

// Reusing the exact same objects on each Get detects accidental cache mutation.
type replayProcessStats struct {
	procs []mapstr.M
	roots []mapstr.M
	err   error
}

func (s *replayProcessStats) Get() ([]mapstr.M, []mapstr.M, error) {
	return s.procs, s.roots, s.err
}

type transformReporter struct {
	events []mb.Event
	accept bool
}

func (r *transformReporter) Event(e mb.Event) bool {
	r.events = append(r.events, e)
	return r.accept
}

func (r *transformReporter) Error(error) bool { return r.accept }

func fixtureTransformMetricSet(instances []ArtifactInstCheck, stats *replayProcessStats) *MetricSet {
	m := &MetricSet{
		stats: stats, artifactInsts: instances,
		pidToPorts: map[int][]string{}, cmdlineToInstId: map[string]string{}, portToInstId: map[string][]string{},
		cmdlineTransforms: map[string]*regexp.Regexp{}, cmdlineReplacements: map[string]string{},
	}
	for _, inst := range instances {
		if inst.CmdlineTransform != nil && inst.CmdlineTransform.Pattern != "" {
			m.cmdlineTransforms[inst.InstanceId] = regexp.MustCompile(inst.CmdlineTransform.Pattern)
			m.cmdlineReplacements[inst.InstanceId] = inst.CmdlineTransform.Replacement
		}
	}
	m.buildCmdlineToInstIdIndex()
	m.buildPortToInstIdIndex()
	return m
}

func TestCmdlineTransformRules(t *testing.T) {
	for _, tc := range []struct{ name, pattern, replacement, input, want string }{
		{"remove dynamic argument", ` --server\.port=[^ ]+`, "", "java --server.port=8080", "java"},
		{"capture groups", `(app)-(\d+)`, "$1", "app-123", "app"},
		{"named group", `(?P<service>app)-\d+`, "${service}", "app-123", "app"},
		{"all matches", `\d+`, "N", "app-12 worker-34", "app-N worker-N"},
		{"no match", `port=\d+`, "", "java", "java"},
		{"empty pattern disabled", "", "ignored", "java", "java"},
		{"empty input", `java`, "app", "", ""},
		{"literal dollar", `java`, "$$java", "java", "$java"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fixtureTransformMetricSet([]ArtifactInstCheck{{InstanceId: "inst", CmdlineTransform: &CmdlineTransform{Pattern: tc.pattern, Replacement: tc.replacement}}}, nil)
			assert.Equal(t, tc.want, m.transformCmdline("inst", tc.input))
			assert.Equal(t, tc.input, m.transformCmdline("unconfigured", tc.input))
		})
	}
}

func TestCmdlineTransformInitialization(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transform interface{}
		invalid   bool
	}{
		{"not configured", nil, false},
		{"empty object", map[string]interface{}{}, false},
		{"empty pattern", map[string]interface{}{"pattern": "", "replacement": "ignored"}, false},
		{"empty replacement", map[string]interface{}{"pattern": "java", "replacement": ""}, false},
		{"invalid regexp", map[string]interface{}{"pattern": "[", "replacement": ""}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst := map[string]interface{}{"instanceId": "diagnostic-instance"}
			if tc.transform != nil {
				inst["cmdlineTransform"] = tc.transform
			}
			cfg, err := conf.NewConfigFrom(map[string]interface{}{
				"module": "system", "metricsets": []string{"process"}, "processes": []string{".*"},
				"process.cgroups.enabled": false, "artifactInsts": []interface{}{inst},
			})
			require.NoError(t, err)
			_, _, err = mb.NewModule(cfg, mb.Registry)
			if tc.invalid {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "diagnostic-instance")
				assert.Contains(t, err.Error(), "cmdlineTransform.pattern")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCmdlineTransformMissingFields(t *testing.T) {
	m := fixtureTransformMetricSet([]ArtifactInstCheck{{InstanceId: "inst", CmdlineTransform: &CmdlineTransform{Pattern: ".", Replacement: "X"}}}, nil)
	for _, root := range []mapstr.M{nil, {}, {"process": mapstr.M{}}, {"process": mapstr.M{"command_line": 12}}} {
		before := root.Clone()
		if root == nil {
			before = nil
		}
		m.transformProcessCmdline(root, "inst")
		assert.Equal(t, before, root)
	}
}

func TestCmdlineTransformFetchSingleInstanceIsolation(t *testing.T) {
	const raw = "java -jar app.jar --server.port=8080"
	for _, exact := range []bool{false, true} {
		t.Run(map[bool]string{false: "keyword", true: "exact"}[exact], func(t *testing.T) {
			inst := ArtifactInstCheck{InstanceId: "inst", CmdlineTransform: &CmdlineTransform{Pattern: ` --server\.port=\d+`, Replacement: ""}}
			if exact {
				inst.ProcessList = []ProcessCheckItem{{Cmdline: raw}}
			} else {
				inst.ProcessMatchGroups = []ProcessMatchGroup{{Cmdline: []string{"--server.port=8080"}}}
			}
			stats := &replayProcessStats{procs: []mapstr.M{{"alive_state": int64(0)}}, roots: []mapstr.M{{"process": mapstr.M{"pid": 101, "command_line": raw}}}}
			original := stats.roots[0].Clone()
			m := fixtureTransformMetricSet([]ArtifactInstCheck{inst}, stats)
			var previous *transformReporter
			for fetch := 0; fetch < 2; fetch++ {
				r := &transformReporter{accept: true}
				require.NoError(t, m.Fetch(r))
				require.Len(t, r.events, 1, "original cmdline must remain available for liveness and matching")
				value, err := r.events[0].RootFields.GetValue("process.command_line")
				require.NoError(t, err)
				assert.Equal(t, "java -jar app.jar", value)
				assert.Equal(t, "inst", r.events[0].RootFields["instanceId"])
				assert.Equal(t, original, stats.roots[0], "Fetch must not modify provider/cached process fields")
				if previous != nil {
					_, err = r.events[0].RootFields.Put("process.command_line", "changed by consumer")
					require.NoError(t, err)
					old, err := previous.events[0].RootFields.GetValue("process.command_line")
					require.NoError(t, err)
					assert.Equal(t, "java -jar app.jar", old, "previous event must remain independent")
				}
				previous = r
			}
		})
	}
}

func TestCmdlineTransformFetchMultipleInstances(t *testing.T) {
	const raw = "java --port=8080 --worker=2"
	instances := []ArtifactInstCheck{
		{InstanceId: "A", ProcessList: []ProcessCheckItem{{Cmdline: "old-A", Ports: []string{"8080"}}}, CmdlineTransform: &CmdlineTransform{Pattern: ` --port=\d+`, Replacement: ""}},
		{InstanceId: "B", ProcessList: []ProcessCheckItem{{Cmdline: "old-B", Ports: []string{"8080"}}}, CmdlineTransform: &CmdlineTransform{Pattern: ` --worker=\d+`, Replacement: ""}},
		{InstanceId: "unmatched", ProcessList: []ProcessCheckItem{{Cmdline: "old-C", Ports: []string{"9090"}}}, CmdlineTransform: &CmdlineTransform{Pattern: `old`, Replacement: "dead"}},
	}
	stats := &replayProcessStats{procs: []mapstr.M{{"alive_state": int64(0)}}, roots: []mapstr.M{{"process": mapstr.M{"pid": 101, "command_line": raw}}}}
	m := fixtureTransformMetricSet(instances, stats)
	m.pidToPorts[101] = []string{"8080"}
	for fetch := 0; fetch < 2; fetch++ {
		r := &transformReporter{accept: true}
		require.NoError(t, m.Fetch(r))
		require.Len(t, r.events, 3)
		got := map[string]string{}
		for _, event := range r.events {
			value, err := event.RootFields.GetValue("process.command_line")
			require.NoError(t, err)
			got[event.RootFields["instanceId"].(string)] = value.(string)
			_, hasInternal := event.MetricSetFields["_matched_instance_ids"]
			assert.False(t, hasInternal)
		}
		assert.Equal(t, map[string]string{"A": "java --worker=2", "B": "java --port=8080", "unmatched": "dead-C"}, got)
		original, err := stats.roots[0].GetValue("process.command_line")
		require.NoError(t, err)
		assert.Equal(t, raw, original)
	}
}

func TestCmdlineTransformFetchNoInstanceAndProviderError(t *testing.T) {
	stats := &replayProcessStats{procs: []mapstr.M{{}}, roots: []mapstr.M{{"process": mapstr.M{"command_line": "synthetic-unmatched"}}}}
	m := fixtureTransformMetricSet(nil, stats)
	r := &transformReporter{accept: true}
	require.NoError(t, m.Fetch(r))
	require.Len(t, r.events, 1)
	assert.Equal(t, "", r.events[0].RootFields["instanceId"])
	value, err := r.events[0].RootFields.GetValue("process.command_line")
	require.NoError(t, err)
	assert.Equal(t, "synthetic-unmatched", value)
	stats.err = errors.New("synthetic stats failure")
	assert.EqualError(t, m.Fetch(r), "process stats: synthetic stats failure")
}
