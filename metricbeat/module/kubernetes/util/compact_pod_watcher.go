package util

import (
	"context"
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type compactPodContainer struct {
	name      string
	image     string
	resources core.ResourceRequirements
}

type compactPodStatus struct {
	name string
	id   string
}

type compactMetadataPod struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	node       string
	ip         string
	hostIP     string
	reason     string
	phase      core.PodPhase
	conditions []core.PodCondition
	containers []compactPodContainer
	init       []compactPodContainer
	statuses   []compactPodStatus
	initStatus []compactPodStatus
}

func compactPodObject(object interface{}) (interface{}, error) {
	if tombstone, ok := object.(cache.DeletedFinalStateUnknown); ok {
		projected, err := compactPodObject(tombstone.Obj)
		tombstone.Obj = projected
		return tombstone, err
	}
	if _, compact := object.(*compactMetadataPod); compact {
		return object, nil
	}
	pod, ok := object.(*core.Pod)
	if !ok {
		return nil, fmt.Errorf("unexpected pod metadata object %T", object)
	}
	projected := &compactMetadataPod{
		TypeMeta: pod.TypeMeta, ObjectMeta: pod.ObjectMeta, node: pod.Spec.NodeName,
		ip: pod.Status.PodIP, hostIP: pod.Status.HostIP, reason: pod.Status.Reason, phase: pod.Status.Phase,
		conditions: pod.Status.Conditions,
	}
	projected.ManagedFields = nil
	containers := func(values []core.Container) []compactPodContainer {
		if len(values) == 0 {
			return nil
		}
		result := make([]compactPodContainer, len(values))
		for position, value := range values {
			result[position] = compactPodContainer{name: value.Name, image: value.Image, resources: value.Resources}
		}
		return result
	}
	statuses := func(values []core.ContainerStatus) []compactPodStatus {
		if len(values) == 0 {
			return nil
		}
		result := make([]compactPodStatus, len(values))
		for position, value := range values {
			result[position] = compactPodStatus{name: value.Name, id: value.ContainerID}
		}
		return result
	}
	projected.containers, projected.init = containers(pod.Spec.Containers), containers(pod.Spec.InitContainers)
	projected.statuses, projected.initStatus = statuses(pod.Status.ContainerStatuses), statuses(pod.Status.InitContainerStatuses)
	return projected, nil
}

func expandPodObject(object interface{}) interface{} {
	if tombstone, ok := object.(cache.DeletedFinalStateUnknown); ok {
		return expandPodObject(tombstone.Obj)
	}
	compact, ok := object.(*compactMetadataPod)
	if !ok {
		return object
	}
	pod := &core.Pod{TypeMeta: compact.TypeMeta, ObjectMeta: compact.ObjectMeta}
	pod.Spec.NodeName = compact.node
	pod.Status = core.PodStatus{PodIP: compact.ip, HostIP: compact.hostIP, Reason: compact.reason, Phase: compact.phase, Conditions: compact.conditions}
	containers := func(values []compactPodContainer) []core.Container {
		if len(values) == 0 {
			return nil
		}
		result := make([]core.Container, len(values))
		for position, value := range values {
			result[position] = core.Container{Name: value.name, Image: value.image, Resources: value.resources}
		}
		return result
	}
	statuses := func(values []compactPodStatus) []core.ContainerStatus {
		if len(values) == 0 {
			return nil
		}
		result := make([]core.ContainerStatus, len(values))
		for position, value := range values {
			result[position] = core.ContainerStatus{Name: value.name, ContainerID: value.id}
		}
		return result
	}
	pod.Spec.Containers, pod.Spec.InitContainers = containers(compact.containers), containers(compact.init)
	pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses = statuses(compact.statuses), statuses(compact.initStatus)
	return pod
}

type expandedPodStore struct{ cache.Store }

func (store expandedPodStore) List() []interface{} {
	items := store.Store.List()
	for position, object := range items {
		items[position] = expandPodObject(object)
	}
	return items
}

func (store expandedPodStore) Get(object interface{}) (interface{}, bool, error) {
	value, exists, err := store.Store.Get(object)
	return expandPodObject(value), exists, err
}

func (store expandedPodStore) GetByKey(key string) (interface{}, bool, error) {
	value, exists, err := store.Store.GetByKey(key)
	return expandPodObject(value), exists, err
}

type compactPodWatcher struct {
	client     k8sclient.Interface
	controller cache.Controller
	store      cache.Store
	handler    kubernetes.ResourceEventHandler
	ctx        context.Context
	cancel     context.CancelFunc
	start      sync.Once
	startErr   error
}

func newCompactPodWatcher(client k8sclient.Interface, options kubernetes.WatchOptions) kubernetes.Watcher {
	ctx, cancel := context.WithCancel(context.Background())
	watcher := &compactPodWatcher{client: client, ctx: ctx, cancel: cancel, handler: kubernetes.NoOpEventHandlerFuncs{}}
	pods := client.CoreV1().Pods(options.Namespace)
	selectNode := func(list *metav1.ListOptions) {
		if options.Node != "" {
			list.FieldSelector = "spec.nodeName=" + options.Node
		}
	}
	source := &cache.ListWatch{
		ListFunc: func(list metav1.ListOptions) (runtime.Object, error) {
			selectNode(&list)
			return pods.List(ctx, list)
		},
		WatchFunc: func(list metav1.ListOptions) (watch.Interface, error) {
			selectNode(&list)
			return pods.Watch(ctx, list)
		},
	}
	store, controller := cache.NewTransformingInformer(source, &core.Pod{}, options.SyncTimeout, cache.ResourceEventHandlerFuncs{
		AddFunc: func(object interface{}) { watcher.handler.OnAdd(expandPodObject(object)) },
		DeleteFunc: func(object interface{}) {
			watcher.handler.OnDelete(expandPodObject(object))
		},
		UpdateFunc: func(previous, next interface{}) {
			oldPod, newPod := expandPodObject(previous).(*core.Pod), expandPodObject(next).(*core.Pod)
			updated := oldPod.ResourceVersion != newPod.ResourceVersion
			if options.IsUpdated != nil {
				updated = options.IsUpdated(oldPod, newPod)
			}
			if updated || options.HonorReSyncs {
				watcher.handler.OnUpdate(newPod)
			}
		},
	}, compactPodObject)
	watcher.store, watcher.controller = expandedPodStore{store}, controller
	return watcher
}

func (watcher *compactPodWatcher) AddEventHandler(handler kubernetes.ResourceEventHandler) {
	watcher.handler = handler
}

func (watcher *compactPodWatcher) Store() cache.Store { return watcher.store }

func (watcher *compactPodWatcher) Client() k8sclient.Interface { return watcher.client }

func (watcher *compactPodWatcher) Start() error {
	watcher.start.Do(func() {
		go watcher.controller.Run(watcher.ctx.Done())
		if !cache.WaitForCacheSync(watcher.ctx.Done(), watcher.controller.HasSynced) {
			watcher.startErr = fmt.Errorf("pod metadata informer unable to sync cache")
		}
	})
	return watcher.startErr
}

func (watcher *compactPodWatcher) Stop() { watcher.cancel() }
