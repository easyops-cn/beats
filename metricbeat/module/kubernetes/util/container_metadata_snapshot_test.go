package util

import (
	"testing"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

func TestContainerMetadataSnapshotSeparatesMutableContainerFields(t *testing.T) {
	for _, ecs := range []interface{}{nil, mapstr.M{"runtime": "containerd"}, map[string]interface{}{"runtime": "containerd"}} {
		pod := mapstr.M{"kubernetes": mapstr.M{"namespace": "default", "labels": mapstr.M{"app": "test"}}}
		if ecs != nil {
			pod["container"] = ecs
		}
		first, second := containerMetadataSnapshot(pod), containerMetadataSnapshot(pod)
		_, err := first.Put("container.id", "one")
		require.NoError(t, err)
		_, err = second.Put("container.id", "two")
		require.NoError(t, err)
		value, err := first.GetValue("container.id")
		require.NoError(t, err)
		require.Equal(t, "one", value)
		_, err = pod.GetValue("container.id")
		require.Error(t, err)
		event := first.Clone()
		_, err = event.Put("kubernetes.labels.app", "changed")
		require.NoError(t, err)
		value, err = second.GetValue("kubernetes.labels.app")
		require.NoError(t, err)
		require.Equal(t, "test", value)
		first["extra"] = "isolated"
		require.NotContains(t, second, "extra")
	}
}

func TestPodContainerMetadataKeysDoesNotMutateInformerPod(t *testing.T) {
	backing := []kubernetes.Container{{Name: "app"}, {Name: "untouched"}}
	pod := &kubernetes.Pod{}
	pod.Namespace = "test"
	pod.Name = "pod"
	pod.Spec.Containers = backing[:1]
	pod.Spec.InitContainers = []kubernetes.Container{{Name: "init"}}
	require.Equal(t, []string{"test:pod:", "test:pod:app", "test:pod:init"}, podContainerMetadataKeys(pod))
	require.Equal(t, "untouched", backing[1].Name)
	require.Len(t, pod.Spec.Containers, 1)
	require.Equal(t, []string{"::"}, podContainerMetadataKeys(&kubernetes.Pod{}))
}
