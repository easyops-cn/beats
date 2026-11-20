package util

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

func sharedMetadataFixture() mapstr.M {
	return mapstr.M{
		"kubernetes": mapstr.M{
			"namespace": "ns", "pod": mapstr.M{"name": "pod", "uid": "pod-uid"},
			"node":        mapstr.M{"name": "node", "labels": mapstr.M{"zone": "zone-a"}},
			"workload":    mapstr.M{"name": "app", "kind": "deployment", "uid": "app-uid"},
			"labels":      mapstr.M{"app.example.io/name": "demo", "other": strings.Repeat("x", 128)},
			"annotations": mapstr.M{"description": "test"},
		},
		"container": mapstr.M{"id": "id", "cpu": mapstr.M{"usage": 1}, "image": mapstr.M{"name": "image"}},
		"service":   mapstr.M{"type": "original", "name": "service"},
		"host":      mapstr.M{"name": "host"},
	}
}

func metadataPipelineEvent(t *testing.T, enrichment *enricher, metricset string, shared bool) mapstr.M {
	t.Helper()
	fields := mapstr.M{
		"name": "sample", "value": 7,
		mb.ModuleDataKey: mapstr.M{"namespace": "metric-namespace", "node": mapstr.M{"name": "metric-node", "metric": true}},
	}
	if shared {
		enrichment.EnrichSharedMetadata([]mapstr.M{fields})
	} else {
		enrichment.EnrichProjected([]mapstr.M{fields}, func(string) bool { return true })
	}
	var event mb.Event
	if metricset == "volume" {
		event = mb.TransformMapStrToEvent("kubernetes", fields, nil)
		event.RootFields.DeepUpdate(mapstr.M{"orchestrator": mapstr.M{"cluster": mapstr.M{"name": "test"}}})
	} else {
		var err error
		event, err = CreateEvent(fields, "kubernetes."+metricset)
		require.NoError(t, err)
	}
	switch metricset {
	case "container", "state_container", "pod":
		event.RootFields.DeepUpdate(mapstr.M{"container": mapstr.M{"name": "reported", "cpu": mapstr.M{"usage": 2}, "image": mapstr.M{"name": "reported-image"}}})
	case "state_deployment", "state_replicaset", "state_daemonset", "state_statefulset":
		DuplicateWorkloadInfo(event.MetricSetFields, "name", event)
	}
	return event.BeatEvent("kubernetes", metricset).Fields.Clone()
}

func TestSharedMetadataPipelineMatchesClonedAndPreservesSnapshot(t *testing.T) {
	for _, metricset := range []string{"node", "container", "pod", "volume", "state_node", "state_pod", "state_container", "state_deployment", "state_replicaset", "state_daemonset", "state_statefulset"} {
		t.Run(metricset, func(t *testing.T) {
			source := sharedMetadataFixture()
			original := source.Clone()
			enrichment := &enricher{metadata: map[string]mapstr.M{"test": source}, index: func(mapstr.M) string { return "test" }, isPod: metricset == "pod" || metricset == "state_pod" || metricset == "volume"}
			expected := metadataPipelineEvent(t, enrichment, metricset, false)
			for attempt := 0; attempt < 3; attempt++ {
				require.Equal(t, expected, metadataPipelineEvent(t, enrichment, metricset, true))
				require.Equal(t, original, source)
			}
		})
	}
}

func TestSharedMetadataConcurrentUpdatesAndEvents(t *testing.T) {
	source := sharedMetadataFixture()
	enrichment := &enricher{metadata: map[string]mapstr.M{"test": source}, index: func(mapstr.M) string { return "test" }}
	var workers sync.WaitGroup
	for worker := 0; worker < 5; worker++ {
		workers.Add(1)
		go func(writer bool) {
			defer workers.Done()
			for iteration := 0; iteration < 50; iteration++ {
				if writer {
					next := sharedMetadataFixture()
					enrichment.Lock()
					enrichment.metadata["test"] = next
					enrichment.Unlock()
				} else {
					metadataPipelineEvent(t, enrichment, "container", true)
				}
			}
		}(worker == 0)
	}
	workers.Wait()
	require.Equal(t, sharedMetadataFixture(), source)
}

func TestSharedMetadataSnapshotCopiesOnlyMutableBranches(t *testing.T) {
	source := sharedMetadataFixture()
	snapshot := snapshotEventMetadata(source)
	sourceK8s := source["kubernetes"].(mapstr.M)
	copyK8s := snapshot["kubernetes"].(mapstr.M)
	require.Equal(t, fmt.Sprintf("%p", sourceK8s["labels"]), fmt.Sprintf("%p", copyK8s["labels"]))
	require.NotEqual(t, fmt.Sprintf("%p", sourceK8s), fmt.Sprintf("%p", copyK8s))
	require.Equal(t, fmt.Sprintf("%p", sourceK8s["workload"]), fmt.Sprintf("%p", copyK8s["workload"]))
	require.NotEqual(t, fmt.Sprintf("%p", source["container"]), fmt.Sprintf("%p", snapshot["container"]))
	require.NotEqual(t, fmt.Sprintf("%p", source["service"]), fmt.Sprintf("%p", snapshot["service"]))
}

func TestDuplicateWorkloadInfoCopiesOnlyChangedBranch(t *testing.T) {
	for _, existing := range []interface{}{nil, "invalid", mapstr.M{"name": "before", "kind": "deployment"}, map[string]interface{}{"name": "before", "kind": "deployment"}} {
		module := mapstr.M{"workload": existing, "namespace": "test"}
		event := mb.Event{ModuleFields: module}
		DuplicateWorkloadInfo(mapstr.M{"name": "after"}, "name", event)
		require.Equal(t, "after", module["workload"].(mapstr.M)["name"])
		switch fields := existing.(type) {
		case mapstr.M:
			require.Equal(t, "before", fields["name"])
			require.Equal(t, "deployment", module["workload"].(mapstr.M)["kind"])
		case map[string]interface{}:
			require.Equal(t, "before", fields["name"])
			require.Equal(t, "deployment", module["workload"].(mapstr.M)["kind"])
		}
		require.Equal(t, "test", module["namespace"])
	}
}

func BenchmarkMetadataSnapshot(b *testing.B) {
	for _, width := range []int{8, 32, 128} {
		source := sharedMetadataFixture()
		labels := source["kubernetes"].(mapstr.M)["labels"].(mapstr.M)
		for label := 0; label < width; label++ {
			labels[fmt.Sprintf("label_%d", label)] = strings.Repeat("v", 64)
		}
		for _, mode := range []string{"projected", "shared"} {
			b.Run(fmt.Sprintf("%s/labels-%d", mode, width), func(b *testing.B) {
				b.ReportAllocs()
				for iteration := 0; iteration < b.N; iteration++ {
					if mode == "shared" {
						snapshotEventMetadata(source)
					} else {
						cloneProjectedMetadata(source, "", false, func(string) bool { return true })
					}
				}
			})
		}
	}
}
