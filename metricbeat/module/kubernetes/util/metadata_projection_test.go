package util

import (
	"strings"
	"sync"
	"testing"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

func TestProjectedMetadataPreservesSelectedFieldsAndIsolation(t *testing.T) {
	source := mapstr.M{
		"kubernetes": mapstr.M{
			"namespace": "ns", "workload": mapstr.M{"name": "app"}, "pod": mapstr.M{"name": "pod"},
			"labels":           mapstr.M{"app.kubernetes.io/name": "demo", "other": "unused"},
			"namespace_labels": mapstr.M{"team": "operations"}, "annotations": mapstr.M{"large": strings.Repeat("x", 4096)},
		},
		"container": mapstr.M{"id": "test", "args": []interface{}{"one", mapstr.M{"two": "value"}}},
	}
	original := source.Clone()
	selected := "kubernetes.labels.app.kubernetes.io/name"
	required := func(path string) bool { return path == selected || strings.HasPrefix(selected, path+".") }
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for event := 0; event < 20; event++ {
				result := cloneProjectedMetadata(source, "", false, required).(mapstr.M)
				k8s := result["kubernetes"].(mapstr.M)
				require.Equal(t, mapstr.M{"app.kubernetes.io/name": "demo"}, k8s["labels"])
				require.NotContains(t, k8s, "annotations")
				require.NotContains(t, k8s, "namespace_labels")
				require.Equal(t, "app", k8s["workload"].(mapstr.M)["name"])
				k8s["labels"].(mapstr.M)["app.kubernetes.io/name"] = "changed"
				k8s["workload"].(mapstr.M)["name"] = "changed"
				result["container"].(mapstr.M)["args"].([]interface{})[1].(mapstr.M)["two"] = "changed"
			}
		}()
	}
	workers.Wait()
	require.Equal(t, original, source)
	require.Equal(t, source, cloneProjectedMetadata(source, "", false, func(string) bool { return true }))
}
