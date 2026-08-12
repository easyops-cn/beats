package util

import (
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

type workloadIdentity struct {
	Kind   string
	Name   string
	UID    string
	Source string
}

type workloadResolver struct {
	sync.RWMutex
	replicaSets cache.Store
	jobs        cache.Store
	confirmed   map[types.UID]workloadIdentity
}

func newWorkloadResolver(replicaSets, jobs cache.Store) *workloadResolver {
	return &workloadResolver{
		replicaSets: replicaSets,
		jobs:        jobs,
		confirmed:   make(map[types.UID]workloadIdentity),
	}
}

func (r *workloadResolver) resolve(pod *kubernetes.Pod) (workloadIdentity, bool) {
	if pod == nil || pod.UID == "" {
		return workloadIdentity{}, false
	}

	r.RLock()
	identity, ok := r.confirmed[pod.UID]
	r.RUnlock()
	if ok {
		return identity, true
	}

	owner, ok := controllerOwner(pod.OwnerReferences)
	if !ok {
		return workloadIdentity{}, false
	}

	switch owner.Kind {
	case "ReplicaSet":
		identity, ok = r.resolveReplicaSet(pod.Namespace, owner)
	case "Job":
		identity, ok = r.resolveJob(pod.Namespace, owner)
	case "Deployment", "StatefulSet", "DaemonSet":
		identity, ok = directWorkload(owner)
	default:
		return workloadIdentity{}, false
	}
	if !ok {
		return workloadIdentity{}, false
	}

	r.Lock()
	r.confirmed[pod.UID] = identity
	r.Unlock()
	return identity, true
}

func (r *workloadResolver) resolveReplicaSet(namespace string, owner metav1.OwnerReference) (workloadIdentity, bool) {
	object, exists, err := r.replicaSets.GetByKey(namespace + "/" + owner.Name)
	if err != nil || !exists {
		return workloadIdentity{}, false
	}
	replicaSet, ok := object.(*kubernetes.ReplicaSet)
	if !ok || replicaSet.UID != owner.UID {
		return workloadIdentity{}, false
	}

	parent, hasParent := controllerOwner(replicaSet.OwnerReferences)
	if !hasParent {
		return workloadIdentity{Kind: "replicaset", Name: owner.Name, UID: string(owner.UID), Source: "pod_owner"}, true
	}
	if parent.Kind != "Deployment" || parent.UID == "" || parent.UID == replicaSet.UID {
		return workloadIdentity{}, false
	}
	identity, ok := directWorkload(parent)
	if !ok {
		return workloadIdentity{}, false
	}
	identity.Source = "pod_owner_replicaset_cache"
	return identity, true
}

func (r *workloadResolver) resolveJob(namespace string, owner metav1.OwnerReference) (workloadIdentity, bool) {
	object, exists, err := r.jobs.GetByKey(namespace + "/" + owner.Name)
	if err != nil || !exists {
		return workloadIdentity{}, false
	}
	job, ok := object.(*kubernetes.Job)
	if !ok || job.UID != owner.UID {
		return workloadIdentity{}, false
	}

	parent, hasParent := controllerOwner(job.OwnerReferences)
	if !hasParent {
		return workloadIdentity{Kind: "job", Name: owner.Name, UID: string(owner.UID), Source: "pod_owner"}, true
	}
	if parent.Kind != "CronJob" || parent.UID == "" || parent.UID == job.UID {
		return workloadIdentity{}, false
	}
	identity, ok := directWorkload(parent)
	if !ok {
		return workloadIdentity{}, false
	}
	identity.Source = "pod_owner_job_cache"
	return identity, true
}

func (r *workloadResolver) deletePod(uid types.UID) {
	if uid == "" {
		return
	}
	r.Lock()
	delete(r.confirmed, uid)
	r.Unlock()
}

func controllerOwner(references []metav1.OwnerReference) (metav1.OwnerReference, bool) {
	for _, reference := range references {
		if reference.Controller != nil && *reference.Controller {
			return reference, true
		}
	}
	return metav1.OwnerReference{}, false
}

func directWorkload(owner metav1.OwnerReference) (workloadIdentity, bool) {
	if owner.Name == "" || owner.UID == "" {
		return workloadIdentity{}, false
	}
	switch owner.Kind {
	case "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob":
		return workloadIdentity{Kind: strings.ToLower(owner.Kind), Name: owner.Name, UID: string(owner.UID), Source: "pod_owner"}, true
	default:
		return workloadIdentity{}, false
	}
}

func enrichPodWorkload(meta mapstr.M, pod *kubernetes.Pod, resolver *workloadResolver) {
	_ = meta.Delete("kubernetes.workload")
	if resolver == nil {
		return
	}
	identity, ok := resolver.resolve(pod)
	if !ok {
		return
	}
	meta.DeepUpdate(mapstr.M{
		"kubernetes": mapstr.M{
			"workload": mapstr.M{
				"kind":   identity.Kind,
				"name":   identity.Name,
				"uid":    identity.UID,
				"source": identity.Source,
			},
		},
	})
}
