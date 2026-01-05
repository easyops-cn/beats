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
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

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

var (
	debugf = logp.MakeDebug("system.process")
)

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
// ProcessInfo stores complete process information for matching
type ProcessInfo struct {
	Cmdline          string
	ProcessName      string
	WorkingDirectory string
}

type AliveProcessData struct {
	ProcessNames map[string]bool // Process name set (O(1) lookup)
	Cmdlines     map[string]bool // Command line set (O(1) lookup)
	Ports        map[string]bool // Port set (O(1) lookup)
	ProcessInfos []ProcessInfo   // Complete process information for matching
}

// NewAliveProcessData creates a new AliveProcessData instance
func NewAliveProcessData() *AliveProcessData {
	return &AliveProcessData{
		ProcessNames: make(map[string]bool),
		Cmdlines:     make(map[string]bool),
		Ports:        make(map[string]bool),
		ProcessInfos: make([]ProcessInfo, 0),
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

	// Port to instance ID mapping (mapping B)
	portToInstId map[string][]string // Port → instance ID list (multiple matches)
}

// New creates and returns a new MetricSet.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	config := defaultConfig
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	sysModule, ok := base.Module().(resolve.Resolver)
	if !ok {
		return nil, fmt.Errorf("module does not implement resolve.Resolver interface")
	}
	sys := sysModule
	enableCgroups := false
	if runtime.GOOS == "linux" {
		if config.Cgroups == nil || *config.Cgroups {
			enableCgroups = true
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
		portToInstId:    make(map[string][]string),
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
		// Non-fatal error, continue running
		debugf("Port watcher initialization failed, will use cmdline-only check: %v", err)
	}

	// Build performance optimization index
	m.buildCmdlineToInstIdIndex()
	m.buildPortToInstIdIndex()

	return m, nil
}

// initPortWatcher initializes the port watcher if port collection is needed
func (m *MetricSet) initPortWatcher() error {
	if !m.needPortCollection() {
		return nil // Port collection not needed, return directly
	}

	watcher := &procs.ProcessesWatcher{}
	if err := watcher.Init(procs.ProcsConfig{Enabled: true}); err != nil {
		return fmt.Errorf("failed to initialize port watcher: %w", err)
	}

	m.portWatcher = watcher
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
}

// buildPortToInstIdIndex builds a fast lookup index for port to instance ID (mapping B)
// Supports multiple instance IDs per port with deduplication
func (m *MetricSet) buildPortToInstIdIndex() {
	for _, inst := range m.artifactInsts {
		for _, proc := range inst.ProcessList {
			for _, port := range proc.Ports {
				if port != "" {
					instIds := m.portToInstId[port]
					// Check if instance ID already exists to avoid duplicates
					found := false
					for _, id := range instIds {
						if id == inst.InstanceId {
							found = true
							break
						}
					}
					if !found {
						m.portToInstId[port] = append(instIds, inst.InstanceId)
					}
				}
			}
		}
	}
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

	return nil
}

// collectPortsForTransport collects ports for a specific transport protocol
func (m *MetricSet) collectPortsForTransport(transport applayer.Transport) error {
	ports, err := m.portWatcher.GetLocalPortToPIDMapping(transport)
	if err != nil {
		return fmt.Errorf("failed to get %s ports: %w", transport, err)
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
		if !portField.IsValid() {
			return 0
		}

		// Try to get value through Interface() first (safer)
		if portField.CanInterface() {
			if port, ok := portField.Interface().(uint16); ok {
				return port
			}
		}

		// If CanInterface() returns false, we need to use unsafe
		// But first, we need to make sure the value is addressable
		// If not, create a copy
		var addrValue reflect.Value
		if portField.CanAddr() {
			addrValue = portField
		} else {
			// Create an addressable copy of the struct
			// This happens when endpoint comes from a map range (unaddressable)
			structCopy := reflect.New(v.Type()).Elem()
			// Check if v can be assigned to structCopy before Set operation
			if v.Type().AssignableTo(structCopy.Type()) && structCopy.CanSet() {
				structCopy.Set(v)
				addrValue = structCopy.FieldByName("port")
			} else {
				return 0
			}
		}

		// Now we can safely use UnsafeAddr()
		if addrValue.IsValid() && addrValue.CanAddr() {
			portPtr := unsafe.Pointer(addrValue.UnsafeAddr())
			// Ensure pointer is valid before dereferencing
			if portPtr != nil {
				return *(*uint16)(portPtr)
			}
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
		}
	}

	// Get all process data
	procs, roots, err := m.stats.Get()
	if err != nil {
		return fmt.Errorf("process stats: %w", err)
	}

	// Build alive process data structure (performance optimization)
	// Note: procs contains MetricSetFields (system.process.*), roots contains RootFields (process.*)
	aliveData := m.buildAliveProcessData(procs, roots)

	// Iterate through each instance and perform liveness check
	var allDeadProcs []DeadProcessInfo
	for _, inst := range m.artifactInsts {
		deadProcs := m.checkInstanceAlive(inst, aliveData)
		allDeadProcs = append(allDeadProcs, deadProcs...)
	}

	// Add instanceId dimension to normal processes
	// Note: procs contains MetricSetFields (system.process.*), roots contains RootFields (process.*)
	m.addInstanceIdDimension(procs, roots)

	// Report normal process metrics
	for i := range procs {
		// Check if there are multiple matched instance IDs
		matchedInstIdsVal, hasMultiple := procs[i]["_matched_instance_ids"]

		if hasMultiple {
			// Multiple instance IDs matched, clone and report for each
			matchedInstIds, ok := matchedInstIdsVal.([]string)
			if !ok || len(matchedInstIds) == 0 {
				// Type error or empty, fallback to single instance handling
				if roots[i] == nil {
					roots[i] = mapstr.M{}
				}
				roots[i].Put("instanceId", "")
				// Remove temporary field
				procs[i].Delete("_matched_instance_ids")
				if !r.Event(mb.Event{
					MetricSetFields: procs[i],
					RootFields:      roots[i],
				}) {
					return nil
				}
				continue
			}

			// Clone and report for each instance ID
			for _, instId := range matchedInstIds {
				procCopy := procs[i].Clone()
				var rootCopy mapstr.M
				if roots[i] == nil {
					rootCopy = mapstr.M{}
				} else {
					rootCopy = roots[i].Clone()
				}

				// Remove temporary field and set instanceId
				procCopy.Delete("_matched_instance_ids")
				procCopy.Put("instanceId", instId)
				rootCopy.Put("instanceId", instId)

				if !r.Event(mb.Event{
					MetricSetFields: procCopy,
					RootFields:      rootCopy,
				}) {
					return nil
				}
			}
		} else {
			// Single or no instance ID, normal reporting
			if roots[i] == nil {
				roots[i] = mapstr.M{}
			}
			if instanceId, exists := procs[i]["instanceId"]; exists {
				roots[i].Put("instanceId", instanceId)
			} else {
				roots[i].Put("instanceId", "")
			}

			if !r.Event(mb.Event{
				MetricSetFields: procs[i],
				RootFields:      roots[i],
			}) {
				return nil
			}
		}
	}

	// Report abnormal process metrics
	for _, deadProc := range allDeadProcs {
		if !r.Event(m.buildDeadProcessEvent(deadProc)) {
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
// procs contains MetricSetFields (system.process.*), roots contains RootFields (process.*)
func (m *MetricSet) buildAliveProcessData(procs []mapstr.M, roots []mapstr.M) *AliveProcessData {
	data := NewAliveProcessData()

	for idx := range procs {
		// Get corresponding root fields (contains process.* ECS fields)
		var root mapstr.M
		if idx < len(roots) {
			root = roots[idx]
		}
		if root == nil {
			continue // Skip if no root fields
		}

		var cmdline string
		var processName string
		var workingDirectory string
		var ports []string

		// Extract process name from root (ECS format)
		if nameVal, err := root.GetValue("process.name"); err == nil {
			if nameStr, ok := nameVal.(string); ok && nameStr != "" {
				processName = nameStr
				data.ProcessNames[nameStr] = true
			}
		}

		// Extract command line from root (ECS format)
		if cmdlineVal, err := root.GetValue("process.command_line"); err == nil {
			if cmdlineStr, ok := cmdlineVal.(string); ok && cmdlineStr != "" {
				cmdline = cmdlineStr
				data.Cmdlines[cmdline] = true
			}
		}

		// Extract working directory from root (ECS format)
		if wdVal, err := root.GetValue("process.working_directory"); err == nil {
			if wdStr, ok := wdVal.(string); ok && wdStr != "" {
				workingDirectory = wdStr
			}
		}

		// Extract PID from root (ECS format)
		pidVal, err := root.GetValue("process.pid")
		if err != nil {
			// Try direct "pid" field as last resort
			pidVal, err = root.GetValue("pid")
		}
		if err != nil {
			continue // Skip port extraction if no PID
		}

		var pidInt int
		switch v := pidVal.(type) {
		case int:
			pidInt = v
		case int64:
			pidInt = int(v)
		case int32:
			pidInt = int(v)
		case float64:
			pidInt = int(v)
		default:
			continue // Skip unsupported PID type
		}

		if pidInt > 0 {
			ports = m.getProcessPorts(pidInt)
			for _, port := range ports {
				data.Ports[port] = true
			}
		}

		// Store complete process information for matching
		if cmdline != "" {
			data.ProcessInfos = append(data.ProcessInfos, ProcessInfo{
				Cmdline:          cmdline,
				ProcessName:      processName,
				WorkingDirectory: workingDirectory,
			})
		}
	}

	return data
}

// checkInstanceAlive checks the liveness status of a single instance
func (m *MetricSet) checkInstanceAlive(
	inst ArtifactInstCheck,
	aliveData *AliveProcessData,
) []DeadProcessInfo {
	// Branch A: processMatchGroups is not empty (higher priority)
	if len(inst.ProcessMatchGroups) > 0 {
		return m.checkProcessMatchGroups(inst, aliveData)
	}
	// Branch B: check processList
	return m.checkProcessList(inst, aliveData)
}

// checkProcessMatchGroups checks if all groups have at least one matching process
// Returns dead process info if any group has no matching process
func (m *MetricSet) checkProcessMatchGroups(
	inst ArtifactInstCheck,
	aliveData *AliveProcessData,
) []DeadProcessInfo {
	if len(inst.ProcessMatchGroups) == 0 {
		return nil
	}

	var deadProcs []DeadProcessInfo

	for _, group := range inst.ProcessMatchGroups {
		// Filter empty keywords
		keywords := filterEmptyStrings(group.Keywords)
		if len(keywords) == 0 {
			continue
		}

		// Check if any process matches all keywords in this group
		found := false
		for _, procInfo := range aliveData.ProcessInfos {
			if matchAllKeywords(keywords, procInfo) {
				found = true
				break
			}
		}

		// If no process matches this group, report as dead
		if !found {
			deadProcs = append(deadProcs, DeadProcessInfo{
				InstanceId: inst.InstanceId,
				Identifier: "/" + strings.Join(keywords, "/"),
			})
		}
	}

	return deadProcs
}

// filterEmptyStrings filters out empty strings from slice
func filterEmptyStrings(strs []string) []string {
	result := make([]string, 0, len(strs))
	for _, s := range strs {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// matchAllKeywords checks if process matches all keywords
func matchAllKeywords(keywords []string, procInfo ProcessInfo) bool {
	for _, keyword := range keywords {
		if !containsKeyword(keyword, procInfo) {
			return false
		}
	}
	return true
}

// containsKeyword checks if keyword exists in cmdline, processName or workingDirectory
func containsKeyword(keyword string, procInfo ProcessInfo) bool {
	if strings.Contains(procInfo.Cmdline, keyword) {
		return true
	}
	if procInfo.ProcessName != "" && strings.Contains(procInfo.ProcessName, keyword) {
		return true
	}
	if procInfo.WorkingDirectory != "" && strings.Contains(procInfo.WorkingDirectory, keyword) {
		return true
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
		if port != "" && alivePorts[port] {
			return true
		}
	}

	return false
}

// addInstanceIdDimension adds instanceId dimension to processes
// procs contains MetricSetFields (system.process.*), roots contains RootFields (process.*)
func (m *MetricSet) addInstanceIdDimension(
	procs []mapstr.M,
	roots []mapstr.M,
) {
	for i := range procs {
		// Get corresponding root fields (contains process.* ECS fields)
		if i >= len(roots) || roots[i] == nil {
			continue
		}

		// Extract cmdline from root (process.command_line)
		cmdlineVal, err := roots[i].GetValue("process.command_line")
		if err != nil {
			continue
		}

		cmdline, ok := cmdlineVal.(string)
		if !ok || cmdline == "" {
			continue
		}

		// Step 1: Try exact cmdline match (highest priority)
		if instanceId, exists := m.cmdlineToInstId[cmdline]; exists {
			_, _ = procs[i].Put("instanceId", instanceId)
			continue
		}

		// Step 2: Try ProcessMatchGroups matching (fallback 1)
		// Extract process name and working directory for matching
		processName := ""
		if nameVal, err := roots[i].GetValue("process.name"); err == nil {
			if nameStr, ok := nameVal.(string); ok {
				processName = nameStr
			}
		}
		workingDirectory := ""
		if wdVal, err := roots[i].GetValue("process.working_directory"); err == nil {
			if wdStr, ok := wdVal.(string); ok {
				workingDirectory = wdStr
			}
		}
		procInfo := ProcessInfo{
			Cmdline:          cmdline,
			ProcessName:      processName,
			WorkingDirectory: workingDirectory,
		}
		instanceId := m.findInstanceIdByProcessMatchGroups(procInfo)
		if instanceId != "" {
			_, _ = procs[i].Put("instanceId", instanceId)
			continue
		}

		// Step 3: Try port matching (fallback 2, may return multiple instance IDs)
		instanceIds := m.findInstanceIdsByPort(roots[i])
		if len(instanceIds) > 0 {
			if len(instanceIds) == 1 {
				// Single match, set instanceId directly
				_, _ = procs[i].Put("instanceId", instanceIds[0])
			} else {
				// Multiple matches, store in temporary field for later processing
				_, _ = procs[i].Put("_matched_instance_ids", instanceIds)
			}
		}
	}
}

// findInstanceIdsByPort finds instance IDs by port matching
// Returns all matching instance IDs where ALL process ports match the instance's configured port list
func (m *MetricSet) findInstanceIdsByPort(root mapstr.M) []string {
	// Extract PID from root (process.pid)
	pidVal, err := root.GetValue("process.pid")
	if err != nil {
		// Try direct "pid" field as last resort
		pidVal, err = root.GetValue("pid")
	}
	if err != nil {
		return nil
	}

	var pidInt int
	switch v := pidVal.(type) {
	case int:
		pidInt = v
	case int64:
		pidInt = int(v)
	case int32:
		pidInt = int(v)
	case float64:
		pidInt = int(v)
	default:
		return nil
	}

	if pidInt <= 0 {
		return nil
	}

	// Get ports for this PID
	processPorts := m.getProcessPorts(pidInt)
	if len(processPorts) == 0 {
		return nil
	}

	// Filter out empty ports
	filteredProcessPorts := []string{}
	processPortSet := make(map[string]bool)
	for _, port := range processPorts {
		if port != "" {
			filteredProcessPorts = append(filteredProcessPorts, port)
			processPortSet[port] = true
		}
	}

	if len(filteredProcessPorts) == 0 {
		return nil
	}

	// Check each instance: ALL process ports must be in one of the instance's ProcessCheckItem port lists
	instIdSet := make(map[string]bool)
	for _, inst := range m.artifactInsts {
		// Check each ProcessCheckItem in this instance
		for _, procItem := range inst.ProcessList {
			// Collect ports for this ProcessCheckItem
			procItemPortSet := make(map[string]bool)
			for _, port := range procItem.Ports {
				if port != "" {
					procItemPortSet[port] = true
				}
			}

			// If this ProcessCheckItem has no ports configured, skip it
			if len(procItemPortSet) == 0 {
				continue
			}

			// Require exact port match: the process port set must equal the configured port set
			if len(procItemPortSet) != len(filteredProcessPorts) {
				continue
			}

			allMatched := true
			for _, port := range filteredProcessPorts {
				if !procItemPortSet[port] {
					allMatched = false
					break
				}
			}

			if allMatched {
				// Found a matching ProcessCheckItem, add instance ID and break
				instIdSet[inst.InstanceId] = true
				break // Only need to match one ProcessCheckItem per instance
			}
		}
	}

	// Convert to slice
	if len(instIdSet) == 0 {
		return nil
	}
	result := make([]string, 0, len(instIdSet))
	for instId := range instIdSet {
		result = append(result, instId)
	}
	return result
}

// findInstanceIdByProcessMatchGroups finds instance ID by matching ProcessMatchGroups
// Returns the first matching instance ID, or empty string if no match
func (m *MetricSet) findInstanceIdByProcessMatchGroups(procInfo ProcessInfo) string {
	for i := range m.artifactInsts {
		inst := &m.artifactInsts[i]
		if len(inst.ProcessMatchGroups) == 0 {
			continue
		}

		// Check if this process matches ANY group in this instance
		for _, group := range inst.ProcessMatchGroups {
			keywords := filterEmptyStrings(group.Keywords)
			if len(keywords) == 0 {
				continue
			}
			if matchAllKeywords(keywords, procInfo) {
				return inst.InstanceId
			}
		}
	}
	return ""
}

// buildDeadProcessEvent builds an event for a dead/abnormal process
func (m *MetricSet) buildDeadProcessEvent(deadProc DeadProcessInfo) mb.Event {
	metricSetFields := mapstr.M{
		"alive_state": int64(1), // 1 indicates abnormal
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
