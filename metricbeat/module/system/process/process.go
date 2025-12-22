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
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
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

var (
	debugf = logp.MakeDebug("system.process")
	// Custom file logger for process module
	fileLogger     *os.File
	fileLoggerOnce sync.Once
	logFileMutex   sync.Mutex
)

// initFileLogger initializes the custom file logger
func initFileLogger() {
	fileLoggerOnce.Do(func() {
		logPath := "/usr/local/easyops/easy_metric_sampler/log/metricbeat.log"

		// Ensure directory exists
		dir := filepath.Dir(logPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			// Fallback to standard logger if directory creation fails
			logp.NewLogger("system.process").Warnf("Failed to create log directory %s: %v, using standard logger", dir, err)
			return
		}

		// Open or create log file (append mode)
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			// Fallback to standard logger if file creation fails
			logp.NewLogger("system.process").Warnf("Failed to open log file %s: %v, using standard logger", logPath, err)
			return
		}

		fileLogger = f
	})
}

// fileDebugf writes debug messages to the custom log file
func fileDebugf(format string, args ...interface{}) {
	// Also use standard logger
	debugf(format, args...)

	// Write to custom file if available
	if fileLogger != nil {
		logFileMutex.Lock()
		defer logFileMutex.Unlock()

		timestamp := time.Now().Format("2006-01-02 15:04:05.000")
		message := fmt.Sprintf(format, args...)
		logLine := fmt.Sprintf("[%s] [DEBUG] [system.process] %s\n", timestamp, message)

		_, err := fileLogger.WriteString(logLine)
		if err != nil {
			// If write fails, try to reopen the file
			logp.NewLogger("system.process").Warnf("Failed to write to log file: %v", err)
		}
	}
}

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
	// Initialize custom file logger
	initFileLogger()

	config := defaultConfig
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	sys := base.Module().(resolve.Resolver)
	enableCgroups := false
	if runtime.GOOS == "linux" {
		if config.Cgroups == nil || *config.Cgroups {
			enableCgroups = true
			fileDebugf("process cgroup data collection is enabled, using hostfs='%v'", sys.ResolveHostFS(""))
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
		fileDebugf("Port watcher initialization failed, will use cmdline-only check: %v", err)
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
	fileDebugf("Port watcher initialized successfully")
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
	fileDebugf("Building cmdlineToInstId index, total instances: %d", len(m.artifactInsts))
	for _, inst := range m.artifactInsts {
		fileDebugf("Processing instance: instanceId=%s, checkProcessNames=%v, processList_count=%d",
			inst.InstanceId, inst.CheckProcessNames, len(inst.ProcessList))
		for i, proc := range inst.ProcessList {
			if proc.Cmdline != "" {
				m.cmdlineToInstId[proc.Cmdline] = inst.InstanceId
				fileDebugf("  [%d] Added to index: instanceId=%s, cmdline=%s, ports=%v",
					i, inst.InstanceId, proc.Cmdline, proc.Ports)
			} else {
				fileDebugf("  [%d] Skipped empty cmdline", i)
			}
		}
	}
	fileDebugf("Built cmdlineToInstId index with %d entries", len(m.cmdlineToInstId))
}

// collectProcessPorts collects listening ports for all processes (cross-platform support)
func (m *MetricSet) collectProcessPorts() error {
	if m.portWatcher == nil {
		fileDebugf("collectProcessPorts: portWatcher is nil, skipping")
		return nil // Port watcher not initialized, skip
	}

	// Clear cache
	oldSize := len(m.pidToPorts)
	m.pidToPorts = make(map[int][]string)
	fileDebugf("collectProcessPorts: cleared pidToPorts cache (old_size=%d)", oldSize)

	// Collect TCP ports
	tcpCountBefore := len(m.pidToPorts)
	if err := m.collectPortsForTransport(applayer.TransportTCP); err != nil {
		fileDebugf("Failed to collect TCP ports: %v", err)
		// Continue trying UDP, don't return error directly
	} else {
		tcpCountAfter := len(m.pidToPorts)
		fileDebugf("TCP port collection: added %d new PIDs (total=%d)", tcpCountAfter-tcpCountBefore, tcpCountAfter)
	}

	// Collect UDP ports
	udpCountBefore := len(m.pidToPorts)
	if err := m.collectPortsForTransport(applayer.TransportUDP); err != nil {
		fileDebugf("Failed to collect UDP ports: %v", err)
		// Non-fatal error, continue running
	} else {
		udpCountAfter := len(m.pidToPorts)
		fileDebugf("UDP port collection: added %d new PIDs (total=%d)", udpCountAfter-udpCountBefore, udpCountAfter)
	}

	// Calculate total ports
	totalPorts := 0
	for _, ports := range m.pidToPorts {
		totalPorts += len(ports)
	}
	fileDebugf("Collected ports for %d processes, total ports=%d", len(m.pidToPorts), totalPorts)
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
			structCopy.Set(v)
			addrValue = structCopy.FieldByName("port")
		}

		// Now we can safely use UnsafeAddr()
		if addrValue.IsValid() && addrValue.CanAddr() {
			portPtr := unsafe.Pointer(addrValue.UnsafeAddr())
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
	fetchStartTime := time.Now()
	// Port collection (if needed)
	needPortCheck := m.needPortCheck()
	fileDebugf("Fetch: port collection check - needPortCheck=%v, portWatcher=%v", needPortCheck, m.portWatcher != nil)
	if needPortCheck && m.portWatcher != nil {
		if err := m.collectProcessPorts(); err != nil {
			fileDebugf("Port collection failed, continuing with cmdline-only check: %v", err)
			// Non-fatal error, continue running
		} else {
			fileDebugf("Port collection completed successfully, pidToPorts_size=%d", len(m.pidToPorts))
		}
	} else if needPortCheck {
		fileDebugf("Port collection needed but portWatcher is nil, will skip port checks")
	}

	// Get all process data
	fileDebugf("Fetch: starting metric collection")
	procs, roots, err := m.stats.Get()
	if err != nil {
		fileDebugf("Fetch: ERROR getting process stats: %v", err)
		return errors.Wrap(err, "process stats")
	}
	fileDebugf("Fetch: retrieved %d processes", len(procs))

	// Build alive process data structure (performance optimization)
	// Note: procs contains MetricSetFields (system.process.*), roots contains RootFields (process.*)
	aliveData := m.buildAliveProcessData(procs, roots)

	// Iterate through each instance and perform liveness check
	fileDebugf("Fetch: checking %d instances for liveness", len(m.artifactInsts))
	fileDebugf("  Alive data summary: names=%d, cmdlines=%d, ports=%d", len(aliveData.ProcessNames), len(aliveData.Cmdlines), len(aliveData.Ports))
	var allDeadProcs []DeadProcessInfo
	checkStartTime := time.Now()
	for i, inst := range m.artifactInsts {
		fileDebugf("Fetch: checking instance [%d/%d]: instanceId=%s", i+1, len(m.artifactInsts), inst.InstanceId)
		deadProcs := m.checkInstanceAlive(inst, aliveData)
		allDeadProcs = append(allDeadProcs, deadProcs...)
		fileDebugf("Fetch: instance [%d] check completed, found %d dead processes", i+1, len(deadProcs))
	}
	checkDuration := time.Since(checkStartTime)
	fileDebugf("Fetch: total dead processes found: %d (check duration: %v)", len(allDeadProcs), checkDuration)

	// Add instanceId dimension to normal processes
	// Note: procs contains MetricSetFields (system.process.*), roots contains RootFields (process.*)
	fileDebugf("Fetch: adding instanceId dimension to %d processes", len(procs))
	m.addInstanceIdDimension(procs, roots)

	// Report normal process metrics
	fileDebugf("Fetch: reporting %d normal process metrics", len(procs))
	reportedNormalCount := 0
	withInstanceIdCount := 0
	withoutInstanceIdCount := 0
	for i := range procs {
		// Ensure alive_state field exists and is string type for normal processes
		// Convert existing numeric value to string, or set "0" if not exists
		if existingValue, exists := procs[i]["alive_state"]; exists {
			// Convert existing value to string (handles int, int64, float64, etc.)
			procs[i].Put("alive_state", fmt.Sprintf("%v", existingValue))
		} else {
			// Add alive_state field for normal processes (0 = normal, string type for database compatibility)
			procs[i].Put("alive_state", "0")
		}

		// Ensure instanceId is in RootFields for dimension matching
		if instanceId, exists := procs[i]["instanceId"]; exists {
			if roots[i] == nil {
				roots[i] = mapstr.M{}
			}
			roots[i].Put("instanceId", instanceId)
			withInstanceIdCount++
			if i < 5 {
				fileDebugf("  [%d] Reporting normal process with instanceId=%s", i, instanceId)
			}
		} else {
			// Ensure instanceId exists in RootFields even if empty (for frontend compatibility)
			if roots[i] == nil {
				roots[i] = mapstr.M{}
			}
			roots[i].Put("instanceId", "")
			withoutInstanceIdCount++
			if i < 5 {
				fileDebugf("  [%d] Reporting normal process without instanceId", i)
			}
		}

		isOpen := r.Event(mb.Event{
			MetricSetFields: procs[i],
			RootFields:      roots[i],
		})
		if !isOpen {
			fileDebugf("Fetch: reporter closed, stopping normal process reporting at index %d", i)
			return nil
		}
		reportedNormalCount++
	}
	fileDebugf("Fetch: reported %d normal process metrics (with_instanceId=%d, without_instanceId=%d)",
		reportedNormalCount, withInstanceIdCount, withoutInstanceIdCount)

	// Report abnormal process metrics
	fileDebugf("Fetch: reporting %d abnormal process metrics", len(allDeadProcs))
	reportedAbnormalCount := 0
	for i, deadProc := range allDeadProcs {
		fileDebugf("  [%d] Reporting abnormal process: instanceId=%s, identifier=%s",
			i, deadProc.InstanceId, deadProc.Identifier)
		event := m.buildDeadProcessEvent(deadProc)
		isOpen := r.Event(event)
		if !isOpen {
			fileDebugf("Fetch: reporter closed, stopping abnormal process reporting at index %d", i)
			return nil
		}
		reportedAbnormalCount++
	}
	fileDebugf("Fetch: reported %d abnormal process metrics", reportedAbnormalCount)
	fetchDuration := time.Since(fetchStartTime)
	fileDebugf("Fetch: completed successfully - normal=%d, abnormal=%d (total duration: %v)",
		reportedNormalCount, reportedAbnormalCount, fetchDuration)

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
	fileDebugf("Building alive process data from %d processes (procs=%d, roots=%d)", len(procs), len(procs), len(roots))

	// Statistics for debugging
	stats := struct {
		nameFound       int
		nameNotFound    int
		cmdlineFound    int
		cmdlineNotFound int
		pidFound        int
		pidNotFound     int
		portsFound      int
		portsNotFound   int
	}{}

	for idx := range procs {
		// Get corresponding root fields (contains process.* ECS fields)
		var root mapstr.M
		if idx < len(roots) {
			root = roots[idx]
		}
		if root == nil {
			continue // Skip if no root fields
		}

		var name, cmdline string
		var ports []string

		// Extract process name from root (ECS format)
		if nameVal, err := root.GetValue("process.name"); err == nil {
			if nameStr, ok := nameVal.(string); ok && nameStr != "" {
				name = nameStr
				stats.nameFound++
				data.ProcessNames[nameStr] = true
			}
		}
		if name == "" {
			stats.nameNotFound++
		}

		// Extract command line from root (ECS format)
		if cmdlineVal, err := root.GetValue("process.command_line"); err == nil {
			if cmdlineStr, ok := cmdlineVal.(string); ok && cmdlineStr != "" {
				cmdline = cmdlineStr
				stats.cmdlineFound++
				data.Cmdlines[cmdline] = true
			}
		}
		if cmdline == "" {
			stats.cmdlineNotFound++
		}

		// Extract PID from root (ECS format)
		pidVal, err := root.GetValue("process.pid")
		if err != nil {
			// Try direct "pid" field as last resort
			pidVal, err = root.GetValue("pid")
		}
		if err != nil {
			stats.pidNotFound++
			continue // Skip port extraction if no PID
		}
		stats.pidFound++

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
			if len(ports) > 0 {
				stats.portsFound++
				for _, port := range ports {
					data.Ports[port] = true
				}
			} else {
				stats.portsNotFound++
			}
		}
	}

	fileDebugf("Built alive process data: names=%d, cmdlines=%d, ports=%d", len(data.ProcessNames), len(data.Cmdlines), len(data.Ports))
	fileDebugf("  Stats - name: found=%d, not_found=%d", stats.nameFound, stats.nameNotFound)
	fileDebugf("  Stats - cmdline: found=%d, not_found=%d", stats.cmdlineFound, stats.cmdlineNotFound)
	fileDebugf("  Stats - pid: found=%d, not_found=%d", stats.pidFound, stats.pidNotFound)
	fileDebugf("  Stats - ports: found=%d, not_found=%d, pidToPorts_size=%d", stats.portsFound, stats.portsNotFound, len(m.pidToPorts))

	return data
}

// checkInstanceAlive checks the liveness status of a single instance
func (m *MetricSet) checkInstanceAlive(
	inst ArtifactInstCheck,
	aliveData *AliveProcessData,
) []DeadProcessInfo {
	fileDebugf("checkInstanceAlive: starting check for instanceId=%s, checkProcessNames_count=%d, processList_count=%d",
		inst.InstanceId, len(inst.CheckProcessNames), len(inst.ProcessList))
	fileDebugf("  Available alive data: names=%d, cmdlines=%d, ports=%d",
		len(aliveData.ProcessNames), len(aliveData.Cmdlines), len(aliveData.Ports))

	var deadProcs []DeadProcessInfo
	checkStartTime := time.Now()

	// Branch A: checkProcessNames is not empty (higher priority)
	if len(inst.CheckProcessNames) > 0 {
		fileDebugf("checkInstanceAlive: using Branch A (checkProcessNames) for instanceId=%s", inst.InstanceId)
		deadProcs = m.checkProcessNames(inst, aliveData)
	} else {
		// Branch B: check processList
		fileDebugf("checkInstanceAlive: using Branch B (processList) for instanceId=%s", inst.InstanceId)
		deadProcs = m.checkProcessList(inst, aliveData)
	}

	checkDuration := time.Since(checkStartTime)
	fileDebugf("checkInstanceAlive: completed for instanceId=%s, found %d dead processes (duration: %v)",
		inst.InstanceId, len(deadProcs), checkDuration)
	return deadProcs
}

// checkProcessNames checks process names (Branch A)
func (m *MetricSet) checkProcessNames(
	inst ArtifactInstCheck,
	aliveData *AliveProcessData,
) []DeadProcessInfo {
	fileDebugf("checkProcessNames: checking %d process names for instanceId=%s, alive_processes=%d",
		len(inst.CheckProcessNames), inst.InstanceId, len(aliveData.ProcessNames))

	var deadProcs []DeadProcessInfo

	for i, checkName := range inst.CheckProcessNames {
		if checkName == "" {
			fileDebugf("  [%d] Skipped empty checkName", i)
			continue // Skip empty strings
		}

		isAlive := m.isProcessNameAlive(checkName, aliveData.ProcessNames)
		fileDebugf("  [%d] checkName=%s, isAlive=%v", i, checkName, isAlive)

		if !isAlive {
			fileDebugf("  [%d] Process name NOT found: checkName=%s, instanceId=%s", i, checkName, inst.InstanceId)
			deadProcs = append(deadProcs, DeadProcessInfo{
				InstanceId: inst.InstanceId,
				Identifier: checkName,
			})
		} else {
			fileDebugf("  [%d] Process name found alive: checkName=%s", i, checkName)
		}
	}

	fileDebugf("checkProcessNames: completed for instanceId=%s, found %d dead processes", inst.InstanceId, len(deadProcs))
	return deadProcs
}

// isProcessNameAlive checks if a process name is alive (helper method, supports contains matching)
func (m *MetricSet) isProcessNameAlive(checkName string, aliveNames map[string]bool) bool {
	checkedCount := 0
	for aliveName := range aliveNames {
		checkedCount++
		if strings.Contains(aliveName, checkName) {
			fileDebugf("    isProcessNameAlive: MATCH found! checkName=%s, matched_aliveName=%s (checked %d names)",
				checkName, aliveName, checkedCount)
			return true // Found match, return immediately
		}
	}
	fileDebugf("    isProcessNameAlive: NO match for checkName=%s (checked %d names)", checkName, checkedCount)
	return false
}

// checkProcessList checks process list (Branch B)
func (m *MetricSet) checkProcessList(
	inst ArtifactInstCheck,
	aliveData *AliveProcessData,
) []DeadProcessInfo {
	fileDebugf("checkProcessList: checking %d processes for instanceId=%s, alive_cmdlines=%d, alive_ports=%d",
		len(inst.ProcessList), inst.InstanceId, len(aliveData.Cmdlines), len(aliveData.Ports))

	var deadProcs []DeadProcessInfo

	for i, proc := range inst.ProcessList {
		if proc.Cmdline == "" {
			fileDebugf("  [%d] Skipped empty cmdline", i)
			continue // Skip empty command lines
		}

		// Check command line and ports
		cmdlineExists := aliveData.Cmdlines[proc.Cmdline]
		portExists := m.checkPortsExist(proc.Ports, aliveData.Ports)

		fileDebugf("  [%d] Checking process: instanceId=%s, cmdline_len=%d, expected_ports=%v",
			i, inst.InstanceId, len(proc.Cmdline), proc.Ports)
		fileDebugf("    cmdlineExists=%v, portExists=%v", cmdlineExists, portExists)

		if len(proc.Cmdline) > 100 {
			fileDebugf("    cmdline_preview=%s...", proc.Cmdline[:100])
		} else {
			fileDebugf("    cmdline=%s", proc.Cmdline)
		}

		// Only abnormal if both cmdline and port don't exist
		if !cmdlineExists && !portExists {
			fileDebugf("  [%d] Process marked as DEAD: cmdline NOT found AND ports NOT found", i)
			deadProcs = append(deadProcs, DeadProcessInfo{
				InstanceId: inst.InstanceId,
				Identifier: proc.Cmdline,
			})
		} else if cmdlineExists {
			fileDebugf("  [%d] Process is ALIVE: cmdline found", i)
		} else if portExists {
			fileDebugf("  [%d] Process is ALIVE: port found (cmdline not found but port exists)", i)
		}
	}

	fileDebugf("checkProcessList: completed for instanceId=%s, found %d dead processes", inst.InstanceId, len(deadProcs))
	return deadProcs
}

// checkPortsExist checks if ports exist (helper method)
func (m *MetricSet) checkPortsExist(
	expectedPorts []string,
	alivePorts map[string]bool,
) bool {
	// If no ports configured, port check is considered failed
	if len(expectedPorts) == 0 {
		fileDebugf("      checkPortsExist: no ports configured, returning false")
		return false
	}

	fileDebugf("      checkPortsExist: checking %d expected ports against %d alive ports",
		len(expectedPorts), len(alivePorts))

	// Any port exists is sufficient
	for i, port := range expectedPorts {
		if port == "" {
			fileDebugf("        [%d] Skipped empty port", i)
			continue // Skip empty ports
		}
		exists := alivePorts[port]
		fileDebugf("        [%d] port=%s, exists=%v", i, port, exists)
		if exists {
			fileDebugf("      checkPortsExist: found matching port=%s, returning true", port)
			return true // Found one port exists, that's sufficient
		}
	}

	fileDebugf("      checkPortsExist: no matching ports found, returning false")
	return false
}

// addInstanceIdDimension adds instanceId dimension to processes
// procs contains MetricSetFields (system.process.*), roots contains RootFields (process.*)
func (m *MetricSet) addInstanceIdDimension(
	procs []mapstr.M,
	roots []mapstr.M,
) {
	fileDebugf("addInstanceIdDimension: processing %d processes, index_size=%d", len(procs), len(m.cmdlineToInstId))

	matchedCount := 0
	unmatchedCount := 0

	for i := range procs {
		// Get corresponding root fields (contains process.* ECS fields)
		var root mapstr.M
		if i < len(roots) {
			root = roots[i]
		}
		if root == nil {
			continue
		}

		// Extract cmdline from root (process.command_line)
		var cmdline string
		if cmdlineVal, err := root.GetValue("process.command_line"); err == nil {
			if cmdlineStr, ok := cmdlineVal.(string); ok && cmdlineStr != "" {
				cmdline = cmdlineStr
			}
		}

		if cmdline == "" {
			continue // Skip processes without command line
		}

		// Use pre-built index for O(1) lookup
		if instanceId, exists := m.cmdlineToInstId[cmdline]; exists {
			procs[i].Put("instanceId", instanceId)
			matchedCount++
		} else {
			unmatchedCount++
		}
	}

	fileDebugf("addInstanceIdDimension: completed - matched=%d, unmatched=%d", matchedCount, unmatchedCount)
}

// buildDeadProcessEvent builds an event for a dead/abnormal process
func (m *MetricSet) buildDeadProcessEvent(deadProc DeadProcessInfo) mb.Event {
	metricSetFields := mapstr.M{
		"alive_state": "1", // "1" indicates abnormal (use string type for database compatibility)
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
