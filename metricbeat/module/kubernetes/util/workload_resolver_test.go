package util

import (
	"testing"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

func TestWorkloadResolver(t *testing.T) {
	controller := true
	tests := []struct {
		name        string
		pod         *kubernetes.Pod
		replicaSets []*kubernetes.ReplicaSet
		jobs        []*kubernetes.Job
		want        workloadIdentity
		resolved    bool
	}{
		{
			name: "deployment through replicaset",
			pod:  podWithOwner("pod-uid", "ReplicaSet", "auth-server-6b4b46d67b", "rs-uid", &controller),
			replicaSets: []*kubernetes.ReplicaSet{{ObjectMeta: metav1.ObjectMeta{
				Namespace: "default", Name: "auth-server-6b4b46d67b", UID: "rs-uid",
				OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "auth-server", UID: "deployment-uid", Controller: &controller}},
			}}},
			want:     workloadIdentity{Kind: "deployment", Name: "auth-server", UID: "deployment-uid", Source: "pod_owner_replicaset_cache"},
			resolved: true,
		},
		{
			name: "cronjob through job",
			pod:  podWithOwner("pod-uid", "Job", "cleanup-29183820", "job-uid", &controller),
			jobs: []*kubernetes.Job{{ObjectMeta: metav1.ObjectMeta{
				Namespace: "default", Name: "cleanup-29183820", UID: "job-uid",
				OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "cleanup", UID: "cronjob-uid", Controller: &controller}},
			}}},
			want:     workloadIdentity{Kind: "cronjob", Name: "cleanup", UID: "cronjob-uid", Source: "pod_owner_job_cache"},
			resolved: true,
		},
		{
			name: "standalone replicaset",
			pod:  podWithOwner("pod-uid", "ReplicaSet", "standalone", "rs-uid", &controller),
			replicaSets: []*kubernetes.ReplicaSet{{ObjectMeta: metav1.ObjectMeta{
				Namespace: "default", Name: "standalone", UID: "rs-uid",
			}}},
			want:     workloadIdentity{Kind: "replicaset", Name: "standalone", UID: "rs-uid", Source: "pod_owner"},
			resolved: true,
		},
		{
			name:     "statefulset direct owner",
			pod:      podWithOwner("pod-uid", "StatefulSet", "database", "statefulset-uid", &controller),
			want:     workloadIdentity{Kind: "statefulset", Name: "database", UID: "statefulset-uid", Source: "pod_owner"},
			resolved: true,
		},
		{
			name: "cache miss",
			pod:  podWithOwner("pod-uid", "ReplicaSet", "missing", "rs-uid", &controller),
		},
		{
			name: "uid mismatch",
			pod:  podWithOwner("pod-uid", "ReplicaSet", "auth-server-6b4b46d67b", "expected-rs-uid", &controller),
			replicaSets: []*kubernetes.ReplicaSet{{ObjectMeta: metav1.ObjectMeta{
				Namespace: "default", Name: "auth-server-6b4b46d67b", UID: "actual-rs-uid",
			}}},
		},
		{
			name: "owner cycle",
			pod:  podWithOwner("pod-uid", "ReplicaSet", "loop", "rs-uid", &controller),
			replicaSets: []*kubernetes.ReplicaSet{{ObjectMeta: metav1.ObjectMeta{
				Namespace: "default", Name: "loop", UID: "rs-uid",
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "loop", UID: "rs-uid", Controller: &controller}},
			}}},
		},
		{
			name: "unsupported owner",
			pod:  podWithOwner("pod-uid", "CustomWorkload", "custom", "custom-uid", &controller),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			replicaSetStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
			for _, replicaSet := range test.replicaSets {
				require.NoError(t, replicaSetStore.Add(replicaSet))
			}
			jobStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
			for _, job := range test.jobs {
				require.NoError(t, jobStore.Add(job))
			}

			resolver := newWorkloadResolver(replicaSetStore, jobStore)
			got, resolved := resolver.resolve(test.pod)
			require.Equal(t, test.resolved, resolved)
			require.Equal(t, test.want, got)
		})
	}
}

func TestEnrichPodWorkload(t *testing.T) {
	controller := true
	resolver := newWorkloadResolver(cache.NewStore(cache.MetaNamespaceKeyFunc), cache.NewStore(cache.MetaNamespaceKeyFunc))
	meta := mapstr.M{"kubernetes": mapstr.M{"pod": mapstr.M{"name": "database-0"}}}
	enrichPodWorkload(meta, podWithOwner("pod-uid", "StatefulSet", "database", "statefulset-uid", &controller), resolver)

	require.Equal(t, "statefulset", mustValue(t, meta, "kubernetes.workload.kind"))
	require.Equal(t, "database", mustValue(t, meta, "kubernetes.workload.name"))
	require.Equal(t, "statefulset-uid", mustValue(t, meta, "kubernetes.workload.uid"))
	require.Equal(t, "pod_owner", mustValue(t, meta, "kubernetes.workload.source"))
}

func TestEnrichPodWorkloadPrefersControllerChainOverConflictingMetadata(t *testing.T) {
	controller := true
	replicaSetStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	replicaSet := &kubernetes.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "auth-server-6b4b46d67b", UID: "rs-uid",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "auth-server", UID: "deployment-uid", Controller: &controller}},
	}}
	require.NoError(t, replicaSetStore.Add(replicaSet))
	resolver := newWorkloadResolver(replicaSetStore, cache.NewStore(cache.MetaNamespaceKeyFunc))
	meta := mapstr.M{"kubernetes": mapstr.M{
		"deployment": mapstr.M{"name": "auth-server"},
		"replicaset": mapstr.M{"name": "auth-server-6b4b46d67b"},
		"workload":   mapstr.M{"kind": "replicaset", "name": "auth-server-6b4b46d67b"},
	}}
	pod := podWithOwner("pod-uid", "ReplicaSet", replicaSet.Name, string(replicaSet.UID), &controller)

	enrichPodWorkload(meta, pod, resolver)

	require.Equal(t, "auth-server", mustValue(t, meta, "kubernetes.deployment.name"))
	require.Equal(t, "auth-server-6b4b46d67b", mustValue(t, meta, "kubernetes.replicaset.name"))
	require.Equal(t, "deployment", mustValue(t, meta, "kubernetes.workload.kind"))
	require.Equal(t, "auth-server", mustValue(t, meta, "kubernetes.workload.name"))
	require.Equal(t, "deployment-uid", mustValue(t, meta, "kubernetes.workload.uid"))
	require.Equal(t, "pod_owner_replicaset_cache", mustValue(t, meta, "kubernetes.workload.source"))
}

func TestWorkloadResolverSeparatesSameNamedReplicaSetsByNamespace(t *testing.T) {
	controller := true
	replicaSetStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for _, replicaSet := range []*kubernetes.ReplicaSet{
		{ObjectMeta: metav1.ObjectMeta{
			Namespace: "team-a", Name: "auth-server-6b4b46d67b", UID: "rs-a-uid",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "auth-server", UID: "deployment-a-uid", Controller: &controller}},
		}},
		{ObjectMeta: metav1.ObjectMeta{
			Namespace: "team-b", Name: "auth-server-6b4b46d67b", UID: "rs-b-uid",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "auth-server", UID: "deployment-b-uid", Controller: &controller}},
		}},
	} {
		require.NoError(t, replicaSetStore.Add(replicaSet))
	}
	resolver := newWorkloadResolver(replicaSetStore, cache.NewStore(cache.MetaNamespaceKeyFunc))

	podA := podWithOwner("pod-a-uid", "ReplicaSet", "auth-server-6b4b46d67b", "rs-a-uid", &controller)
	podA.Namespace = "team-a"
	podB := podWithOwner("pod-b-uid", "ReplicaSet", "auth-server-6b4b46d67b", "rs-b-uid", &controller)
	podB.Namespace = "team-b"

	identityA, resolvedA := resolver.resolve(podA)
	identityB, resolvedB := resolver.resolve(podB)

	require.True(t, resolvedA)
	require.True(t, resolvedB)
	require.Equal(t, workloadIdentity{Kind: "deployment", Name: "auth-server", UID: "deployment-a-uid", Source: "pod_owner_replicaset_cache"}, identityA)
	require.Equal(t, workloadIdentity{Kind: "deployment", Name: "auth-server", UID: "deployment-b-uid", Source: "pod_owner_replicaset_cache"}, identityB)
}

func TestPodMetadataIndex(t *testing.T) {
	tests := []struct {
		name  string
		event mapstr.M
	}{
		{
			name: "pod metricset",
			event: mapstr.M{
				mb.ModuleDataKey: mapstr.M{"namespace": "default"},
				"name":           "auth-server-pod",
			},
		},
		{
			name: "volume metricset",
			event: mapstr.M{
				"name": "default-token-volume",
				mb.ModuleDataKey: mapstr.M{
					"namespace": "default",
					"pod":       mapstr.M{"name": "auth-server-pod"},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, "default:auth-server-pod", podMetadataIndex(test.event))
		})
	}
}

func TestContainerMetadataIndex(t *testing.T) {
	require.Equal(t, "default:auth-server-pod:auth-server", containerMetadataIndex("default", "auth-server-pod", "auth-server"))
	require.Equal(t, "default:auth-server-pod:", containerMetadataIndex("default", "auth-server-pod", ""))
}

func TestContainerEnricherUsesPodMetadataForAggregateEvents(t *testing.T) {
	podMeta := mapstr.M{"kubernetes": mapstr.M{
		"pod":      mapstr.M{"name": "auth-server-pod"},
		"workload": mapstr.M{"kind": "deployment", "name": "auth-server"},
	}}
	containerMeta := podMeta.Clone()
	_, err := containerMeta.Put("kubernetes.container.id", "container-id")
	require.NoError(t, err)

	enricher := enricher{
		metadata: map[string]mapstr.M{
			containerMetadataIndex("default", "auth-server-pod", ""):            podMeta,
			containerMetadataIndex("default", "auth-server-pod", "auth-server"): containerMeta,
		},
		index: func(event mapstr.M) string {
			return containerMetadataIndex(
				getString(event, mb.ModuleDataKey+".namespace"),
				getString(event, mb.ModuleDataKey+".pod.name"),
				getString(event, "name"),
			)
		},
	}
	events := []mapstr.M{
		{mb.ModuleDataKey: mapstr.M{"namespace": "default", "pod": mapstr.M{"name": "auth-server-pod"}}, "name": "auth-server"},
		{mb.ModuleDataKey: mapstr.M{"namespace": "default", "pod": mapstr.M{"name": "auth-server-pod"}}},
	}

	enricher.Enrich(events)

	for _, event := range events {
		require.Equal(t, "auth-server", mustValue(t, event, mb.ModuleDataKey+".workload.name"))
	}
	require.Equal(t, "container-id", mustValue(t, events[0], mb.ModuleDataKey+".container.id"))
	_, err = events[1].GetValue(mb.ModuleDataKey + ".container.id")
	require.Error(t, err)
}

func TestWorkloadResolverKeepsConfirmedPodIdentityStable(t *testing.T) {
	controller := true
	replicaSetStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	replicaSet := &kubernetes.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "auth-server-6b4b46d67b", UID: "rs-uid",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "auth-server", UID: "deployment-uid", Controller: &controller}},
	}}
	require.NoError(t, replicaSetStore.Add(replicaSet))
	resolver := newWorkloadResolver(replicaSetStore, cache.NewStore(cache.MetaNamespaceKeyFunc))
	pod := podWithOwner("pod-uid", "ReplicaSet", replicaSet.Name, string(replicaSet.UID), &controller)

	want, resolved := resolver.resolve(pod)
	require.True(t, resolved)
	require.NoError(t, replicaSetStore.Delete(replicaSet))
	for iteration := 0; iteration < 10000; iteration++ {
		got, ok := resolver.resolve(pod)
		require.True(t, ok)
		require.Equal(t, want, got)
	}
}

func podWithOwner(podUID, kind, name, ownerUID string, controller *bool) *kubernetes.Pod {
	return &kubernetes.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "pod",
		UID:       types.UID(podUID),
		OwnerReferences: []metav1.OwnerReference{{
			Kind: kind, Name: name, UID: types.UID(ownerUID), Controller: controller,
		}},
	}}
}

func mustValue(t *testing.T, fields mapstr.M, key string) interface{} {
	t.Helper()
	value, err := fields.GetValue(key)
	require.NoError(t, err)
	return value
}
