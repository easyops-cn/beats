package util

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes/metadata"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stest "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

func compactProjectionPod() *core.Pod {
	return &core.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "uid", ResourceVersion: "42", Labels: map[string]string{"app": "test"}, Annotations: map[string]string{"team": "infra"}, ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "test"}}},
		Spec:       core.PodSpec{NodeName: "node", Volumes: []core.Volume{{Name: "volume"}}, Containers: []core.Container{{Name: "app", Image: "image", Env: []core.EnvVar{{Name: "unused", Value: "value"}}, Ports: []core.ContainerPort{{ContainerPort: 80}}}}, InitContainers: []core.Container{{Name: "init", Env: []core.EnvVar{{Name: "unused"}}}}},
		Status:     core.PodStatus{PodIP: "10.0.0.1", Reason: "reason", Conditions: []core.PodCondition{{Type: core.PodReady, Status: core.ConditionTrue, LastTransitionTime: metav1.NewTime(time.Unix(42, 0))}}, ContainerStatuses: []core.ContainerStatus{{Name: "app", ContainerID: "containerd://id"}}, InitContainerStatuses: []core.ContainerStatus{{Name: "init", ContainerID: "containerd://init-id"}}},
	}
}

func TestCompactMetadataPodPreservesMetadataAndOriginal(t *testing.T) {
	pod := compactProjectionPod()
	before := pod.DeepCopy()
	compact, err := compactPodObject(pod)
	require.NoError(t, err)
	projected := expandPodObject(compact).(*core.Pod)
	require.Equal(t, before, pod)
	require.Empty(t, projected.Spec.Containers[0].Env)
	require.Empty(t, projected.Spec.Containers[0].Ports)
	require.Empty(t, projected.Spec.Volumes)
	require.Empty(t, projected.ManagedFields)
	require.Equal(t, pod.Spec.Containers[0].Resources, projected.Spec.Containers[0].Resources)
	client := fake.NewSimpleClientset()
	cfg, err := config.NewConfigFrom(map[string]interface{}{"include_annotations": []string{"*"}})
	require.NoError(t, err)
	generator := metadata.NewPodMetadataGenerator(cfg, nil, client, nil, nil, &metadata.AddResourceMetadataConfig{})
	expected, actual := generator.Generate(pod), generator.Generate(projected)
	enrichPodStatusMetadata(expected, pod)
	enrichPodStatusMetadata(actual, projected)
	require.Equal(t, expected, actual)
	require.Equal(t, podContainerMetadataKeys(pod), podContainerMetadataKeys(projected))
	require.Less(t, int(unsafe.Sizeof(compactMetadataPod{})), int(unsafe.Sizeof(core.Pod{})))
	require.Less(t, int(unsafe.Sizeof(compactPodContainer{})), int(unsafe.Sizeof(core.Container{})))
	tombstone, err := compactPodObject(cache.DeletedFinalStateUnknown{Key: "ns/pod", Obj: pod})
	require.NoError(t, err)
	require.Equal(t, projected, expandPodObject(tombstone))
}

func TestCompactPodWatcherStoreUpdatesDeletionAndCancellation(t *testing.T) {
	pod := compactProjectionPod()
	client := fake.NewSimpleClientset(pod)
	rawWatch := watch.NewRaceFreeFake()
	client.PrependWatchReactor("pods", func(action k8stest.Action) (bool, watch.Interface, error) {
		require.Equal(t, "ns", action.GetNamespace())
		return true, rawWatch, nil
	})
	watcher := newCompactPodWatcher(client, kubernetes.WatchOptions{Namespace: "ns", Node: "node"}).(*compactPodWatcher)
	defer watcher.Stop()
	var adds, updates, deletes int32
	watcher.AddEventHandler(kubernetes.ResourceEventHandlerFuncs{
		AddFunc:    func(object interface{}) { require.IsType(t, &core.Pod{}, object); atomic.AddInt32(&adds, 1) },
		UpdateFunc: func(object interface{}) { require.IsType(t, &core.Pod{}, object); atomic.AddInt32(&updates, 1) },
		DeleteFunc: func(object interface{}) { require.IsType(t, &core.Pod{}, object); atomic.AddInt32(&deletes, 1) },
	})
	require.NoError(t, watcher.Start())
	require.Eventually(t, func() bool { return atomic.LoadInt32(&adds) == 1 }, 3*time.Second, time.Millisecond)
	raw, exists, err := watcher.store.(expandedPodStore).Store.GetByKey("ns/pod")
	require.NoError(t, err)
	require.True(t, exists)
	require.IsType(t, &compactMetadataPod{}, raw)
	view, exists, err := watcher.Store().GetByKey("ns/pod")
	require.NoError(t, err)
	require.True(t, exists)
	require.Empty(t, view.(*core.Pod).Spec.Containers[0].Env)
	require.IsType(t, &core.Pod{}, watcher.Store().List()[0])
	updated := pod.DeepCopy()
	updated.ResourceVersion = "43"
	updated.Labels["app"] = "updated"
	rawWatch.Modify(updated)
	require.Eventually(t, func() bool { return atomic.LoadInt32(&updates) == 1 }, 3*time.Second, time.Millisecond)
	view, _, err = watcher.Store().GetByKey("ns/pod")
	require.NoError(t, err)
	require.Equal(t, "updated", view.(*core.Pod).Labels["app"])
	rawWatch.Delete(updated)
	require.Eventually(t, func() bool { return atomic.LoadInt32(&deletes) == 1 }, 3*time.Second, time.Millisecond)
	require.Empty(t, watcher.Store().List())
	original, err := watcher.Client().CoreV1().Pods("ns").Get(context.Background(), "pod", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, original.Spec.Containers[0].Env)
	watcher.Stop()
	require.Eventually(t, rawWatch.IsStopped, 3*time.Second, time.Millisecond)
}
