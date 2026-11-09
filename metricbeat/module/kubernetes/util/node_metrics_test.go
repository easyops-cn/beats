package util

import (
	"testing"
	"time"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNodeCapacityWarmsLateLeaseWithoutStateNodeMetricset(test *testing.T) {
	node := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node"}, Status: v1.NodeStatus{Capacity: v1.ResourceList{
		v1.ResourceCPU: resource.MustParse("4"), v1.ResourceMemory: resource.MustParse("8Gi"),
	}}}
	client := fake.NewSimpleClientset(node)
	config := &kubernetesConfig{KubeConfig: "node-capacity-test"}
	first, err := newSharedMetadataWatcher(config, "test", client, &kubernetes.Node{}, kubernetes.WatchOptions{})
	require.NoError(test, err)
	defer first.Stop()
	require.NoError(test, first.Start())
	late, err := newSharedMetadataWatcher(config, "test", client, &kubernetes.Node{}, kubernetes.WatchOptions{})
	require.NoError(test, err)
	defer late.Stop()
	repo := NewMetricsRepo()
	warm := trackNodeMetrics(late, repo)
	require.NoError(test, late.Start())
	warm()
	metrics := repo.GetNodeStore("node").GetNodeMetrics()
	require.Equal(test, 4.0, metrics.CoresAllocatable.Value)
	require.Equal(test, float64(8<<30), metrics.MemoryAllocatable.Value)
	node.Status.Capacity[v1.ResourceCPU] = resource.MustParse("8")
	late.(*watcherLease).dispatch((*kubernetes.Node)(node), "update")
	require.Equal(test, 8.0, repo.GetNodeStore("node").GetNodeMetrics().CoresAllocatable.Value)
	late.(*watcherLease).dispatch((*kubernetes.Node)(node), "delete")
	require.Nil(test, repo.GetNodeStore("node").GetNodeMetrics().CoresAllocatable)
}

func TestPodStatusMetadataUsesOnlyKnownReadyTransition(test *testing.T) {
	ready := metav1.NewTime(time.Unix(1000, 0))
	pod := &kubernetes.Pod{Status: v1.PodStatus{Reason: "Evicted", Conditions: []v1.PodCondition{{Type: v1.PodReady, Status: v1.ConditionTrue, LastTransitionTime: ready}}}}
	meta := mapstr.M{}
	enrichPodStatusMetadata(meta, pod)
	require.Equal(test, "Evicted", mustValue(test, meta, "kubernetes.pod.status.reason"))
	require.Equal(test, float64(1000), mustValue(test, meta, "kubernetes.pod.status.ready_time"))
	pod.Status.Reason = ""
	pod.Status.Conditions[0].Status = v1.ConditionFalse
	meta = mapstr.M{}
	enrichPodStatusMetadata(meta, pod)
	require.Equal(test, "", mustValue(test, meta, "kubernetes.pod.status.reason"))
	_, err := meta.GetValue("kubernetes.pod.status.ready_time")
	require.Error(test, err)
}
