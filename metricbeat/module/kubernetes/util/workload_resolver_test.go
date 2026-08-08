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
