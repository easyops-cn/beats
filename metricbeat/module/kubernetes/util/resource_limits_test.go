package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainerResourceLimitsSnapshot(t *testing.T) {
	node := NewNodeStore("node")
	podID := NewPodId("namespace", "pod")
	require.Equal(t, ContainerResourceLimits{}, node.GetContainerResourceLimits(podID, "app"))
	require.Empty(t, node.PodIds())
	pod, _ := node.AddPodStore(podID)
	require.Equal(t, ContainerResourceLimits{}, node.GetContainerResourceLimits(podID, "app"))
	require.Empty(t, pod.ContainerNames())
	container, _ := pod.AddContainerStore("app")
	container.SetContainerMetrics(&ContainerMetrics{CoresLimit: NewFloat64Metric(0), MemoryLimit: NewFloat64Metric(1024)})
	snapshot := node.GetContainerResourceLimits(podID, "app")
	require.Equal(t, ContainerResourceLimits{HasCoresLimit: true, HasMemoryLimit: true, Memory: 1024}, snapshot)
	container.SetContainerMetrics(NewContainerMetrics())
	require.Equal(t, float64(1024), snapshot.Memory)
	require.Equal(t, ContainerResourceLimits{}, node.GetContainerResourceLimits(podID, "app"))
}
