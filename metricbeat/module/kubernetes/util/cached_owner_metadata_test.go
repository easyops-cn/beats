package util

import (
	"testing"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes/metadata"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestCachedOwnerMetadataPreservesConfigurationAndFields(t *testing.T) {
	controller := true
	replicas, jobs := cache.NewStore(cache.MetaNamespaceKeyFunc), cache.NewStore(cache.MetaNamespaceKeyFunc)
	require.NoError(t, replicas.Add(&kubernetes.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "replica", UID: "replica-id",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "app", UID: "deployment-id", Controller: &controller}},
	}}))
	require.NoError(t, jobs.Add(&kubernetes.Job{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "job", UID: "job-id",
		OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "cron", UID: "cron-id", Controller: &controller}},
	}}))
	resolver := newWorkloadResolver(replicas, jobs)
	config := metadata.GetDefaultResourceMetadataConfig()
	config.Deployment, config.CronJob = true, true
	cached := cachedPodMetadataConfig(config, resolver)
	require.False(t, cached.Deployment)
	require.False(t, cached.CronJob)
	require.True(t, config.Deployment)
	require.True(t, config.CronJob)
	require.Same(t, config, cachedPodMetadataConfig(config, nil))
	for _, test := range []struct{ owner, name, uid, field, expected string }{
		{"ReplicaSet", "replica", "replica-id", "deployment.name", "app"},
		{"Job", "job", "job-id", "cronjob.name", "cron"},
	} {
		pod := podWithOwner(test.name+"-pod", test.owner, test.name, test.uid, &controller)
		meta := mapstr.M{}
		enrichPodMetadata(meta, pod, resolver, config)
		require.Equal(t, test.expected, mustValue(t, meta, "kubernetes."+test.field))
		require.Equal(t, test.expected, mustValue(t, meta, "kubernetes.workload.name"))
		disabled := *config
		disabled.Deployment, disabled.CronJob = false, false
		meta = mapstr.M{}
		enrichPodMetadata(meta, pod, resolver, &disabled)
		_, err := meta.GetValue("kubernetes." + test.field)
		require.Error(t, err)
		require.Equal(t, test.expected, mustValue(t, meta, "kubernetes.workload.name"))
	}
}
