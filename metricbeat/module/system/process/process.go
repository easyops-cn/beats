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
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/mb/parse"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos/applayer"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/cgroup"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/process"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/resolve"
)

var debugf = logp.MakeDebug("system.process")

func init() {
	mb.Registry.MustAddMetricSet("system", "process", New,
		mb.WithHostParser(parse.EmptyHostParser),
		mb.DefaultMetricSet(),
	)
}

// DeadProcessInfo represents information about a dead/abnormal process
type DeadProcessInfo struct {
	InstanceId string // Instance ID
	Identifier string // Identifier (process name or command line)
}

// AliveProcessData represents alive process data structure (performance optimized)
type AliveProcessData struct {
	ProcessNames map[string]bool // Process name set (O(1) lookup)
	Cmdlines     map[string]bool // Command line set (O(1) lookup)
	Ports        map[string]bool // Port set (O(1) lookup)
}

// NewAliveProcessData creates a new AliveProcessData instance
func NewAliveProcessData() *AliveProcessData {
	return &AliveProcessData{
		ProcessNames: make(map[string]bool),
		Cmdlines:     make(map[string]bool),
		Ports:        make(map[string]bool),
	}
}

// MetricSet that fetches process metrics.
type MetricSet struct {
	mb.BaseMetricSet
	stats  *process.Stats
	cgroup *cgroup.Reader
	perCPU bool

	// Multi-instance configuration
	artifactInsts []ArtifactInstCheck

	// Performance optimization cache
	pidToPorts map[int][]string // PID → port list

	// Port collection (cross-platform support)
	portWatcher *procs.ProcessesWatcher

	// Pre-compiled matching index (performance optimization)
	cmdlineToInstId map[string]string // Command line → instance ID fast lookup table
}

// New creates and returns a new MetricSet.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	config := defaultConfig
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	sys := base.Module().(resolve.Resolver)
	enableCgroups := false
	if runtime.GOOS == "linux" {
		if config.Cgroups == nil || *config.Cgroups {
			enableCgroups = true
			debugf("process cgroup data collection is enabled, using hostfs='%v'", sys.ResolveHostFS(""))
		}
	}

	// filter empty cmdlines
	checkCmdlines := []string{}
	for _, cmdline := range config.CheckCmdlines {
		if cmdline != "" {
			checkCmdlines = append(checkCmdlines, cmdline)
		}
	}

	m := &MetricSet{
		BaseMetricSet:   base,
		artifactInsts:   config.ArtifactInsts,
		pidToPorts:      make(map[int][]string),
		cmdlineToInstId: make(map[string]string),
		stats: &process.Stats{
			Procs:         config.Procs,
			Hostfs:        sys,
			EnvWhitelist:  config.EnvWhitelist,
			CPUTicks:      config.IncludeCPUTicks || (config.CPUTicks != nil && *config.CPUTicks),
			CacheCmdLine:  config.CacheCmdLine,
			IncludeTop:    config.IncludeTop,
			EnableCgroups: enableCgroups,
			CgroupOpts: cgroup.ReaderOptions{
				RootfsMountpoint:  sys,
				IgnoreRootCgroups: true,
			},
			CheckCmdlines: checkCmdlines,
		},
		perCPU: config.IncludePerCPU,
	}

	// If hostfs is set, we may not want to force the hierarchy override, as the user could be expecting a custom path.
	if !sys.IsSet() {
		override, isset := os.LookupEnv("LIBBEAT_MONITORING_CGROUPS_HIERARCHY_OVERRIDE")
		if isset {
			m.stats.CgroupOpts.CgroupsHierarchyOverride = override
		}
	}

	err := m.stats.Init()
	if err != nil {
		return nil, err
	}

	// Conditionally initialize port watcher (cross-platform support)
	if err := m.initPortWatcher(); err != nil {
		debugf("Port watcher initialization failed, will use cmdline-only check: %v", err)
		// Non-fatal error, continue running
	}

	// Build performance optimization index
	m.buildCmdlineToInstIdIndex()

	return m, nil
}

// initPortWatcher initializes the port watcher if port collection is needed
func (m *MetricSet) initPortWatcher() error {
	if !m.needPortCollection() {
		return nil // Port collection not needed, return directly
	}

	watcher := &procs.ProcessesWatcher{}
	if err := watcher.Init(procs.ProcsConfig{Enabled: true}); err != nil {
		return errors.Wrap(err, "failed to initialize port watcher")
	}

	m.portWatcher = watcher
	debugf("Port watcher initialized successfully")
	return nil
}

// needPortCollection checks if port collection is needed
func (m *MetricSet) needPortCollection() bool {
	for _, inst := range m.artifactInsts {
		for _, proc := range inst.ProcessList {
			if len(proc.Ports) > 0 {
				return true
			}
		}
	}
	return false
}

// buildCmdlineToInstIdIndex builds a fast lookup index for command line to instance ID
func (m *MetricSet) buildCmdlineToInstIdIndex() {
	for _, inst := range m.artifactInsts {
		for _, proc := range inst.ProcessList {
			if proc.Cmdline != "" {
				m.cmdlineToInstId[proc.Cmdline] = inst.InstanceId
			}
		}
	}
	debugf("Built cmdlineToInstId index with %d entries", len(m.cmdlineToInstId))
}

// collectProcessPorts collects listening ports for all processes (cross-platform support)
func (m *MetricSet) collectProcessPorts() error {
	if m.portWatcher == nil {
		return nil // Port watcher not initialized, skip
	}

	// Clear cache
	m.pidToPorts = make(map[int][]string)

	// Collect TCP ports
	if err := m.collectPortsForTransport(applayer.TransportTCP); err != nil {
		debugf("Failed to collect TCP ports: %v", err)
		// Continue trying UDP, don't return error directly
	}

	// Collect UDP ports
	if err := m.collectPortsForTransport(applayer.TransportUDP); err != nil {
		debugf("Failed to collect UDP ports: %v", err)
		// Non-fatal error, continue running
	}

	debugf("Collected ports for %d processes", len(m.pidToPorts))
	return nil
}

// collectPortsForTransport collects ports for a specific transport protocol
func (m *MetricSet) collectPortsForTransport(transport applayer.Transport) error {
	ports, err := m.portWatcher.GetLocalPortToPIDMapping(transport)
	if err != nil {
		return errors.Wrapf(err, "failed to get %s ports", transport)
	}

	// Convert to internal format
	// Note: endpoint is an unexported type from procs package, so we use reflection
	// to access the unexported port field
	for endpoint, pid := range ports {
		port := m.getPortFromEndpoint(endpoint)
		if port > 0 {
			portStr := strconv.Itoa(int(port))
			m.pidToPorts[pid] = append(m.pidToPorts[pid], portStr)
		}
	}

	return nil
}

// getPortFromEndpoint extracts port from endpoint using reflection
// This is necessary because endpoint.port is unexported
func (m *MetricSet) getPortFromEndpoint(endpoint interface{}) uint16 {
	// Use reflection to access unexported port field
	v := reflect.ValueOf(endpoint)
	if v.Kind() == reflect.Struct {
		// Get the port field (unexported, so we need to use unsafe)
		portField := v.FieldByName("port")
		if portField.IsValid() && portField.CanInterface() {
			if port, ok := portField.Interface().(uint16); ok {
				return port
			}
		}
		// If CanInterface() returns false, use unsafe to access the field
		if portField.IsValid() {
			// Use unsafe to read the uint16 value
			portPtr := unsafe.Pointer(portField.UnsafeAddr())
			return *(*uint16)(portPtr)
		}
	}
	return 0
}

// getProcessPorts gets the port list for a process
func (m *MetricSet) getProcessPorts(pid int) []string {
	if ports, exists := m.pidToPorts[pid]; exists {
		return ports
	}
	return []string{} // Return empty slice instead of nil
}

// Fetch fetches metrics for all processes. It iterates over each PID and
// collects process metadata, CPU metrics, and memory metrics.
func (m *MetricSet) Fetch(r mb.ReporterV2) error {
	// Port collection (if needed)
	if m.needPortCheck() && m.portWatcher != nil {
		if err := m.collectProcessPorts(); err != nil {
			debugf("Port collection failed, continuing with cmdline-only check: %v", err)
			// Non-fatal error, continue running
		}
	}

	// Get all process data
	procs, roots, err := m.stats.Get()
	if err != nil {
		return errors.Wrap(err, "process stats")
	}

	// Build alive process data structure (performance optimization)
	aliveData := m.buildAliveProcessData(procs)

	// Iterate through each instance and perform liveness check
	var allDeadProcs []DeadProcessInfo
	for _, inst := range m.artifactInsts {
		deadProcs := m.checkInstanceAlive(inst, aliveData)
		allDeadProcs = append(allDeadProcs, deadProcs...)
	}

	// Add instanceId dimension to normal processes
	m.addInstanceIdDimension(procs)

	// Report normal process metrics
	for i := range procs {
		// Ensure instanceId is in RootFields for dimension matching
		if instanceId, exists := procs[i]["instanceId"]; exists {
			if roots[i] == nil {
				roots[i] = mapstr.M{}
			}
			roots[i].Put("instanceId", instanceId)
		}

		isOpen := r.Event(mb.Event{
			MetricSetFields: procs[i],
			RootFields:      roots[i],
		})
		if !isOpen {
			return nil
		}
	}

	// Report abnormal process metrics
	for _, deadProc := range allDeadProcs {
		event := m.buildDeadProcessEvent(deadProc)
		isOpen := r.Event(event)
		if !isOpen {
			return nil
		}
	}

	return nil
}

// needPortCheck checks if port check is needed
func (m *MetricSet) needPortCheck() bool {
	return m.needPortCollection() // Reuse the initialization check logic
}

// buildAliveProcessData builds alive process data structure (performance optimization core method)
func (m *MetricSet) buildAliveProcessData(procs []mapstr.M) *AliveProcessData {
	data := NewAliveProcessData()

	for _, proc := range procs {
		// Extract process name
		if name, err := proc.GetValue("process.name"); err == nil {
			if nameStr, ok := name.(string); ok && nameStr != "" {
				data.ProcessNames[nameStr] = true
			}
		}

		// Extract command line
		cmdline := m.extractCmdline(proc)
		if cmdline != "" {
			data.Cmdlines[cmdline] = true
		}

		// Extract ports (requires PID)
		if pid, err := proc.GetValue("process.pid"); err == nil {
			if pidInt, ok := pid.(int); ok {
				ports := m.getProcessPorts(pidInt)
				for _, port := range ports {
					data.Ports[port] = true
				}
			}
		}
	}

	debugf("Built alive process data: %d names, %d cmdlines, %d ports",
		len(data.ProcessNames), len(data.Cmdlines), len(data.Ports))

	return data
}

// extractCmdline extracts command line from process data (helper method, handles multiple cases)
func (m *MetricSet) extractCmdline(proc mapstr.M) string {
	// Prefer command_line
	if cmdline, err := proc.GetValue("process.command_line"); err == nil {
		if cmdlineStr, ok := cmdline.(string); ok {
			return cmdlineStr
		}
	}

	// Fallback: use args concatenation
	if args, err := proc.GetValue("process.args"); err == nil {
		if argsSlice, ok := args.([]string); ok {
			return strings.Join(argsSlice, " ")
		}
		// Try interface{} slice
		if argsSlice, ok := args.([]interface{}); ok {
			var strArgs []string
			for _, arg := range argsSlice {
				if argStr, ok := arg.(string); ok {
					strArgs = append(strArgs, argStr)
				}
			}
			if len(strArgs) > 0 {
				return strings.Join(strArgs, " ")
			}
		}
	}

	return ""
}

// checkInstanceAlive checks the liveness status of a single instance
func (m *MetricSet) checkInstanceAlive(
	inst ArtifactInstCheck,
	aliveData *AliveProcessData,
) []DeadProcessInfo {
	var deadProcs []DeadProcessInfo

	// Branch A: checkProcessNames is not empty (higher priority)
	if len(inst.CheckProcessNames) > 0 {
		deadProcs = m.checkProcessNames(inst, aliveData)
	} else {
		// Branch B: check processList
		deadProcs = m.checkProcessList(inst, aliveData)
	}

	return deadProcs
}

// checkProcessNames checks process names (Branch A)
func (m *MetricSet) checkProcessNames(
	inst ArtifactInstCheck,
	aliveData *AliveProcessData,
) []DeadProcessInfo {
	var deadProcs []DeadProcessInfo

	for _, checkName := range inst.CheckProcessNames {
		if checkName == "" {
			continue // Skip empty strings
		}

		if !m.isProcessNameAlive(checkName, aliveData.ProcessNames) {
			deadProcs = append(deadProcs, DeadProcessInfo{
				InstanceId: inst.InstanceId,
				Identifier: checkName,
			})
		}
	}

	return deadProcs
}

// isProcessNameAlive checks if a process name is alive (helper method, supports contains matching)
func (m *MetricSet) isProcessNameAlive(checkName string, aliveNames map[string]bool) bool {
	for aliveName := range aliveNames {
		if strings.Contains(aliveName, checkName) {
			return true // Found match, return immediately
		}
	}
	return false
}

// checkProcessList checks process list (Branch B)
func (m *MetricSet) checkProcessList(
	inst ArtifactInstCheck,
	aliveData *AliveProcessData,
) []DeadProcessInfo {
	var deadProcs []DeadProcessInfo

	for _, proc := range inst.ProcessList {
		if proc.Cmdline == "" {
			continue // Skip empty command lines
		}

		// Check command line and ports
		cmdlineExists := aliveData.Cmdlines[proc.Cmdline]
		portExists := m.checkPortsExist(proc.Ports, aliveData.Ports)

		// Only abnormal if both cmdline and port don't exist
		if !cmdlineExists && !portExists {
			deadProcs = append(deadProcs, DeadProcessInfo{
				InstanceId: inst.InstanceId,
				Identifier: proc.Cmdline,
			})
		}
	}

	return deadProcs
}

// checkPortsExist checks if ports exist (helper method)
func (m *MetricSet) checkPortsExist(
	expectedPorts []string,
	alivePorts map[string]bool,
) bool {
	// If no ports configured, port check is considered failed
	if len(expectedPorts) == 0 {
		return false
	}

	// Any port exists is sufficient
	for _, port := range expectedPorts {
		if port == "" {
			continue // Skip empty ports
		}
		if alivePorts[port] {
			return true // Found one port exists, that's sufficient
		}
	}

	return false
}

// addInstanceIdDimension adds instanceId dimension to processes
func (m *MetricSet) addInstanceIdDimension(
	procs []mapstr.M,
) {
	for i := range procs {
		cmdline := m.extractCmdline(procs[i])
		if cmdline == "" {
			continue // Skip processes without command line
		}

		// Use pre-built index for O(1) lookup
		if instanceId, exists := m.cmdlineToInstId[cmdline]; exists {
			procs[i].Put("instanceId", instanceId)
			debugf("Added instanceId %s to process: cmdline=%s", instanceId, cmdline)
		}
	}
}

// buildDeadProcessEvent builds an event for a dead/abnormal process
func (m *MetricSet) buildDeadProcessEvent(deadProc DeadProcessInfo) mb.Event {
	metricSetFields := mapstr.M{
		"alive_state": 1, // 1 indicates abnormal
	}

	rootFields := mapstr.M{
		"process": mapstr.M{
			"command_line": deadProc.Identifier,
		},
		"instanceId": deadProc.InstanceId,
	}

	return mb.Event{
		MetricSetFields: metricSetFields,
		RootFields:      rootFields,
	}
}
