package util

import (
	"fmt"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	k8sclient "k8s.io/client-go/kubernetes"
)

type watcherKey struct {
	cluster   string
	resource  string
	namespace string
	node      string
	sync      time.Duration
}

var metadataWatchers = struct {
	sync.Mutex
	entries map[watcherKey]*sharedMetadataWatcher
}{entries: make(map[watcherKey]*sharedMetadataWatcher)}

type sharedMetadataWatcher struct {
	kubernetes.Watcher
	startOnce sync.Once
	startErr  error
	handlerMu sync.RWMutex
	handlers  map[*watcherLease]kubernetes.ResourceEventHandler
	refs      int
}

type watcherLease struct {
	*sharedMetadataWatcher
	key      watcherKey
	stopOnce sync.Once
}

func newSharedMetadataWatcher(config *kubernetesConfig, name string, client k8sclient.Interface, resource kubernetes.Resource, options kubernetes.WatchOptions) (kubernetes.Watcher, error) {
	cluster := config.KubeConfig
	if cluster == "" {
		cluster = kubernetes.GetKubeConfigEnvironmentVariable()
	}
	key := watcherKey{cluster: cluster, resource: fmt.Sprintf("%T", resource), namespace: options.Namespace, node: options.Node, sync: options.SyncTimeout}
	metadataWatchers.Lock()
	defer metadataWatchers.Unlock()
	shared := metadataWatchers.entries[key]
	if shared == nil {
		var watcher kubernetes.Watcher
		var err error
		if _, pod := resource.(*kubernetes.Pod); pod {
			watcher = newCompactPodWatcher(client, options)
		} else {
			watcher, err = kubernetes.NewNamedWatcher(name, client, resource, options, nil)
		}
		if err != nil {
			return nil, err
		}
		shared = &sharedMetadataWatcher{Watcher: watcher, handlers: make(map[*watcherLease]kubernetes.ResourceEventHandler)}
		watcher.AddEventHandler(kubernetes.ResourceEventHandlerFuncs{
			AddFunc:    func(object interface{}) { shared.dispatch(object, "add") },
			UpdateFunc: func(object interface{}) { shared.dispatch(object, "update") },
			DeleteFunc: func(object interface{}) { shared.dispatch(object, "delete") },
		})
		metadataWatchers.entries[key] = shared
	}
	shared.refs++
	return &watcherLease{sharedMetadataWatcher: shared, key: key}, nil
}

func (watcher *sharedMetadataWatcher) dispatch(object interface{}, action string) {
	watcher.handlerMu.RLock()
	defer watcher.handlerMu.RUnlock()
	for _, handler := range watcher.handlers {
		switch action {
		case "add":
			handler.OnAdd(object)
		case "update":
			handler.OnUpdate(object)
		case "delete":
			handler.OnDelete(object)
		}
	}
}

func (lease *watcherLease) AddEventHandler(handler kubernetes.ResourceEventHandler) {
	lease.handlerMu.Lock()
	defer lease.handlerMu.Unlock()
	lease.handlers[lease] = handler
}

func (lease *watcherLease) Start() error {
	lease.startOnce.Do(func() { lease.startErr = lease.Watcher.Start() })
	return lease.startErr
}

func (lease *watcherLease) Stop() {
	lease.stopOnce.Do(func() {
		metadataWatchers.Lock()
		defer metadataWatchers.Unlock()
		lease.handlerMu.Lock()
		delete(lease.handlers, lease)
		lease.handlerMu.Unlock()
		lease.refs--
		if lease.refs == 0 {
			lease.Watcher.Stop()
			delete(metadataWatchers.entries, lease.key)
		}
	})
}
