// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package util

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	k8sclient "k8s.io/client-go/kubernetes"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"

	kubernetes2 "github.com/elastic/beats/v7/libbeat/autodiscover/providers/kubernetes"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes/metadata"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

// Enricher takes Kubernetes events and enrich them with k8s metadata
type Enricher interface {
	// Start will start the Kubernetes watcher on the first call, does nothing on the rest
	// errors are logged as warning
	Start()

	// Stop will stop the Kubernetes watcher
	Stop()

	// Enrich the given list of events
	Enrich([]mapstr.M)
}

type kubernetesConfig struct {
	KubeConfig        string                       `config:"kube_config"`
	KubeClientOptions kubernetes.KubeClientOptions `config:"kube_client_options"`

	Node       string        `config:"node"`
	SyncPeriod time.Duration `config:"sync_period"`

	// AddMetadata enables enriching metricset events with metadata from the API server
	AddMetadata         bool                                `config:"add_metadata"`
	AddResourceMetadata *metadata.AddResourceMetadataConfig `config:"add_resource_metadata"`
	Namespace           string                              `config:"namespace"`
}

type enricher struct {
	sync.RWMutex
	metadata            map[string]mapstr.M
	metadataTombstones  map[string]metadataTombstone
	nextMetadataCleanup time.Time
	deletionGracePeriod time.Duration
	updateMetadata      func(map[string]mapstr.M, kubernetes.Resource) []string
	index               func(mapstr.M) string
	watcher             kubernetes.Watcher
	watchersStarted     bool
	watchersStartedLock sync.Mutex
	namespaceWatcher    kubernetes.Watcher
	nodeWatcher         kubernetes.Watcher
	workloadWatchers    []kubernetes.Watcher
	workloadResolver    *workloadResolver
	syncNodeMetrics     func()
	isPod               bool
}

type metadataTombstone struct {
	meta      mapstr.M
	expiresAt time.Time
}

const (
	selector                    = "kubernetes"
	metadataDeletionGracePeriod = time.Minute
)

// NewResourceMetadataEnricher returns an Enricher configured for kubernetes resource events
func newResourceMetadataEnricher(
	base mb.BaseMetricSet,
	res kubernetes.Resource,
	metricsRepo *MetricsRepo,
	nodeScope bool) Enricher {

	config, err := GetValidatedConfig(base)
	if err != nil {
		logp.Info("Kubernetes metricset enriching is disabled")
		return &nilEnricher{}
	}

	watcher, nodeWatcher, namespaceWatcher := getResourceMetadataWatchers(config, res, nodeScope)

	if watcher == nil {
		return &nilEnricher{}
	}

	// GetPodMetaGen requires cfg of type Config
	commonMetaConfig := metadata.Config{}
	if err := base.Module().UnpackConfig(&commonMetaConfig); err != nil {
		logp.Err("Error initializing Kubernetes metadata enricher: %s", err)
		watcher.Stop()
		nodeWatcher.Stop()
		namespaceWatcher.Stop()
		return &nilEnricher{}
	}
	cfg, _ := conf.NewConfigFrom(&commonMetaConfig)

	namespaceMeta := metadata.NewNamespaceMetadataGenerator(config.AddResourceMetadata.Namespace, namespaceWatcher.Store(), watcher.Client())
	serviceMetaGen := metadata.NewServiceMetadataGenerator(cfg, watcher.Store(), namespaceMeta, watcher.Client())

	metaGen := metadata.NewNamespaceAwareResourceMetadataGenerator(cfg, watcher.Client(), namespaceMeta)

	var workloadResolver *workloadResolver
	var workloadWatchers []kubernetes.Watcher
	if _, ok := res.(*kubernetes.Pod); ok {
		workloadResolver, workloadWatchers = newPodWorkloadResolver(config, watcher.Client())
	}
	podMetaGen := metadata.GetPodMetaGen(cfg, watcher, nodeWatcher, namespaceWatcher, cachedPodMetadataConfig(config.AddResourceMetadata, workloadResolver))

	enricher := buildMetadataEnricher(watcher, nodeWatcher, namespaceWatcher,
		// update
		func(m map[string]mapstr.M, r kubernetes.Resource) []string {
			accessor, _ := meta.Accessor(r)
			id := join(accessor.GetNamespace(), accessor.GetName())

			switch r := r.(type) {
			case *kubernetes.Pod:
				podMeta := podMetaGen.Generate(r)
				enrichPodMetadata(podMeta, r, workloadResolver, config.AddResourceMetadata)
				enrichPodStatusMetadata(podMeta, r)
				m[id] = podMeta

			case *kubernetes.Node:
				nodeName := r.GetObjectMeta().GetName()
				metrics := NewNodeMetrics()
				if cpu, ok := r.Status.Capacity["cpu"]; ok {
					if q, err := resource.ParseQuantity(cpu.String()); err == nil {
						metrics.CoresAllocatable = NewFloat64Metric(float64(q.MilliValue()) / 1000)
					}
				}
				if memory, ok := r.Status.Capacity["memory"]; ok {
					if q, err := resource.ParseQuantity(memory.String()); err == nil {
						metrics.MemoryAllocatable = NewFloat64Metric(float64(q.Value()))
					}
				}
				nodeStore, _ := metricsRepo.AddNodeStore(nodeName)
				nodeStore.SetNodeMetrics(metrics)

				m[id] = metaGen.Generate("node", r)

			case *kubernetes.Deployment:
				m[id] = metaGen.Generate("deployment", r)
			case *kubernetes.Job:
				m[id] = metaGen.Generate("job", r)
			case *kubernetes.CronJob:
				m[id] = metaGen.Generate("cronjob", r)
			case *kubernetes.Service:
				m[id] = serviceMetaGen.Generate(r)
			case *kubernetes.StatefulSet:
				m[id] = metaGen.Generate("statefulset", r)
			case *kubernetes.Namespace:
				m[id] = metaGen.Generate("namespace", r)
			case *kubernetes.ReplicaSet:
				m[id] = metaGen.Generate("replicaset", r)
			case *kubernetes.DaemonSet:
				m[id] = metaGen.Generate("daemonset", r)
			case *kubernetes.PersistentVolume:
				m[id] = metaGen.Generate("persistentvolume", r)
			case *kubernetes.PersistentVolumeClaim:
				m[id] = metaGen.Generate("persistentvolumeclaim", r)
			case *kubernetes.StorageClass:
				m[id] = metaGen.Generate("storageclass", r)
			default:
				m[id] = metaGen.Generate(r.GetObjectKind().GroupVersionKind().Kind, r)
			}
			m[id] = metricsRepo.internMetadataLabels(m[id])
			return []string{id}
		},
		// delete
		func(m map[string]mapstr.M, r kubernetes.Resource) []string {
			accessor, _ := meta.Accessor(r)
			if pod, ok := r.(*kubernetes.Pod); ok && workloadResolver != nil {
				workloadResolver.deletePod(pod.UID)
			}

			switch r := r.(type) {
			case *kubernetes.Node:
				nodeName := r.GetObjectMeta().GetName()
				metricsRepo.DeleteNodeStore(nodeName)
			}

			id := join(accessor.GetNamespace(), accessor.GetName())
			return []string{id}
		},
		// index
		func(e mapstr.M) string {
			if _, ok := res.(*kubernetes.Pod); ok {
				return podMetadataIndex(e)
			}
			return join(getString(e, mb.ModuleDataKey+".namespace"), getString(e, "name"))
		},
	)
	enricher.workloadResolver = workloadResolver
	enricher.workloadWatchers = workloadWatchers
	enricher.syncNodeMetrics = trackNodeMetrics(nodeWatcher, metricsRepo)

	// Configure the enricher for Pods, so pod specific metadata ends up in the right place when
	// calling Enrich
	if _, ok := res.(*kubernetes.Pod); ok {
		enricher.isPod = true
		enricher.deletionGracePeriod = metadataDeletionGracePeriod
	}

	return enricher
}

// NewContainerMetadataEnricher returns an Enricher configured for container events
func newContainerMetadataEnricher(
	base mb.BaseMetricSet,
	metricsRepo *MetricsRepo,
	nodeScope bool) Enricher {

	config, err := GetValidatedConfig(base)
	if err != nil {
		logp.Info("Kubernetes metricset enriching is disabled")
		return &nilEnricher{}
	}

	watcher, nodeWatcher, namespaceWatcher := getResourceMetadataWatchers(config, &kubernetes.Pod{}, nodeScope)
	if watcher == nil {
		return &nilEnricher{}
	}

	commonMetaConfig := metadata.Config{}
	if err := base.Module().UnpackConfig(&commonMetaConfig); err != nil {
		logp.Err("Error initializing Kubernetes metadata enricher: %s", err)
		watcher.Stop()
		nodeWatcher.Stop()
		namespaceWatcher.Stop()
		return &nilEnricher{}
	}
	cfg, _ := conf.NewConfigFrom(&commonMetaConfig)

	workloadResolver, workloadWatchers := newPodWorkloadResolver(config, watcher.Client())
	metaGen := metadata.GetPodMetaGen(cfg, watcher, nodeWatcher, namespaceWatcher, cachedPodMetadataConfig(config.AddResourceMetadata, workloadResolver))

	enricher := buildMetadataEnricher(watcher, nodeWatcher, namespaceWatcher,
		// update
		func(m map[string]mapstr.M, r kubernetes.Resource) []string {
			pod, ok := r.(*kubernetes.Pod)
			if !ok {
				base.Logger().Debugf("Error while casting event: %s", ok)
			}
			podMeta := metaGen.Generate(pod)
			enrichPodMetadata(podMeta, pod, workloadResolver, config.AddResourceMetadata)
			podMeta = metricsRepo.internMetadataLabels(podMeta)
			keys := []string{containerMetadataIndex(pod.Namespace, pod.Name, "")}
			m[keys[0]] = podMeta

			statuses := make(map[string]*kubernetes.PodContainerStatus)
			mapStatuses := func(s []kubernetes.PodContainerStatus) {
				for i := range s {
					statuses[s[i].Name] = &s[i]
				}
			}
			mapStatuses(pod.Status.ContainerStatuses)
			mapStatuses(pod.Status.InitContainerStatuses)

			nodeStore, _ := metricsRepo.AddNodeStore(pod.Spec.NodeName)
			podId := NewPodId(pod.Namespace, pod.Name)
			podStore, _ := nodeStore.AddPodStore(podId)

			for _, containers := range [][]kubernetes.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
				for _, container := range containers {
					meta := containerMetadataSnapshot(podMeta)
					metrics := NewContainerMetrics()

					if cpu, ok := container.Resources.Limits["cpu"]; ok {
						if q, err := resource.ParseQuantity(cpu.String()); err == nil {
							metrics.CoresLimit = NewFloat64Metric(float64(q.MilliValue()) / 1000)
						}
					}
					if memory, ok := container.Resources.Limits["memory"]; ok {
						if q, err := resource.ParseQuantity(memory.String()); err == nil {
							metrics.MemoryLimit = NewFloat64Metric(float64(q.Value()))
						}
					}

					containerStore, _ := podStore.AddContainerStore(container.Name)
					containerStore.SetContainerMetrics(metrics)

					if s, ok := statuses[container.Name]; ok {
						// Extracting id and runtime ECS fields from ContainerID
						// which is in the form of <container.runtime>://<container.id>
						split := strings.Index(s.ContainerID, "://")
						if split != -1 {
							kubernetes2.ShouldPut(meta, "container.id", s.ContainerID[split+3:], base.Logger())

							kubernetes2.ShouldPut(meta, "container.runtime", s.ContainerID[:split], base.Logger())
						}
					}

					id := containerMetadataIndex(pod.Namespace, pod.Name, container.Name)
					m[id] = meta
					keys = append(keys, id)
				}
			}
			return keys
		},
		// delete
		func(m map[string]mapstr.M, r kubernetes.Resource) []string {
			pod, ok := r.(*kubernetes.Pod)
			if !ok {
				base.Logger().Debugf("Error while casting event: %s", ok)
			}
			if workloadResolver != nil {
				workloadResolver.deletePod(pod.UID)
			}
			podId := NewPodId(pod.Namespace, pod.Name)
			nodeStore := metricsRepo.GetNodeStore(pod.Spec.NodeName)
			nodeStore.DeletePodStore(podId)

			return podContainerMetadataKeys(pod)
		},
		// index
		func(e mapstr.M) string {
			return containerMetadataIndex(
				getString(e, mb.ModuleDataKey+".namespace"),
				getString(e, mb.ModuleDataKey+".pod.name"),
				getString(e, "name"),
			)
		},
	)
	enricher.workloadResolver = workloadResolver
	enricher.workloadWatchers = workloadWatchers
	enricher.syncNodeMetrics = trackNodeMetrics(nodeWatcher, metricsRepo)
	enricher.deletionGracePeriod = metadataDeletionGracePeriod

	return enricher
}

func newPodWorkloadResolver(config *kubernetesConfig, client k8sclient.Interface) (*workloadResolver, []kubernetes.Watcher) {
	options := kubernetes.WatchOptions{
		SyncTimeout: config.SyncPeriod,
		Namespace:   config.Namespace,
	}
	replicaSetWatcher, err := newSharedMetadataWatcher(config, "resource_metadata_enricher_replicaset", client, &kubernetes.ReplicaSet{}, options)
	if err != nil {
		logp.Warn("Error creating ReplicaSet watcher for workload resolver: %s", err)
		return nil, nil
	}
	jobWatcher, err := newSharedMetadataWatcher(config, "resource_metadata_enricher_job", client, &kubernetes.Job{}, options)
	if err != nil {
		logp.Warn("Error creating Job watcher for workload resolver: %s", err)
		replicaSetWatcher.Stop()
		return nil, nil
	}
	return newWorkloadResolver(replicaSetWatcher.Store(), jobWatcher.Store()), []kubernetes.Watcher{replicaSetWatcher, jobWatcher}
}

func getResourceMetadataWatchers(config *kubernetesConfig, resource kubernetes.Resource, nodeScope bool) (kubernetes.Watcher, kubernetes.Watcher, kubernetes.Watcher) {
	client, err := kubernetes.GetKubernetesClient(config.KubeConfig, config.KubeClientOptions)
	if err != nil {
		logp.Err("Error creating Kubernetes client: %s", err)
		return nil, nil, nil
	}

	options := kubernetes.WatchOptions{
		SyncTimeout: config.SyncPeriod,
		Namespace:   config.Namespace,
	}

	log := logp.NewLogger(selector)
	nodeWatcher, err := newSharedMetadataWatcher(config, "resource_metadata_enricher_node", client, &kubernetes.Node{}, kubernetes.WatchOptions{SyncTimeout: config.SyncPeriod})
	if err != nil {
		logp.Err("Error creating node watcher: %s", err)
		return nil, nil, nil
	}

	// Watch objects in the node only
	if nodeScope {
		nd := &kubernetes.DiscoverKubernetesNodeParams{
			ConfigHost:  config.Node,
			Client:      client,
			IsInCluster: kubernetes.IsInCluster(config.KubeConfig),
			HostUtils:   &kubernetes.DefaultDiscoveryUtils{},
		}
		options.Node, err = kubernetes.DiscoverKubernetesNode(log, nd)
		if err != nil {
			logp.Err("Couldn't discover kubernetes node: %s", err)
			nodeWatcher.Stop()
			return nil, nil, nil
		}
		if net.ParseIP(options.Node) != nil {
			options.Node, err = metadataNodeNameForAddress(options.Node, nodeWatcher)
			if err != nil {
				logp.Warn("Unable to resolve kubelet address to node name; using cluster metadata: %s", err)
				options.Node = ""
			}
		}
	}

	log.Debugf("Initializing a new Kubernetes watcher using host: %v", config.Node)

	watcher, err := newSharedMetadataWatcher(config, "resource_metadata_enricher", client, resource, options)
	if err != nil {
		logp.Err("Error initializing Kubernetes watcher: %s", err)
		nodeWatcher.Stop()
		return nil, nil, nil
	}

	namespaceWatcher, err := newSharedMetadataWatcher(config, "resource_metadata_enricher_namespace", client, &kubernetes.Namespace{}, kubernetes.WatchOptions{
		SyncTimeout: config.SyncPeriod,
	})
	if err != nil {
		logp.Err("Error creating watcher for %T due to error %+v", &kubernetes.Namespace{}, err)
		watcher.Stop()
		nodeWatcher.Stop()
		return nil, nil, nil
	}

	return watcher, nodeWatcher, namespaceWatcher
}

func GetDefaultDisabledMetaConfig() *kubernetesConfig {
	return &kubernetesConfig{
		AddMetadata: false,
	}
}

func GetValidatedConfig(base mb.BaseMetricSet) (*kubernetesConfig, error) {
	config, err := GetConfig(base)
	if err != nil {
		logp.Err("Error while getting config: %v", err)
		return nil, err
	}

	config, err = validateConfig(config)
	if err != nil {
		logp.Err("Error while validating config: %v", err)
		return nil, err
	}
	return config, nil
}

func validateConfig(config *kubernetesConfig) (*kubernetesConfig, error) {
	if !config.AddMetadata {
		return nil, errors.New("metadata enriching is disabled")
	}
	return config, nil
}

func GetConfig(base mb.BaseMetricSet) (*kubernetesConfig, error) {
	config := &kubernetesConfig{
		AddMetadata:         true,
		SyncPeriod:          time.Minute * 10,
		AddResourceMetadata: metadata.GetDefaultResourceMetadataConfig(),
	}
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, errors.New("error unpacking configs")
	}
	if config.Node == "" {
		config.Node = nodeFromMetricsetHost(base.HostData().Host)
	}

	return config, nil
}

func nodeFromMetricsetHost(host string) string {
	if host == "" {
		return ""
	}
	if node, _, err := net.SplitHostPort(host); err == nil {
		return node
	}
	return strings.Trim(host, "[]")
}

func getString(m mapstr.M, key string) string {
	val, err := m.GetValue(key)
	if err != nil {
		return ""
	}

	str, _ := val.(string)
	return str
}

func podMetadataIndex(event mapstr.M) string {
	name := getString(event, mb.ModuleDataKey+".pod.name")
	if name == "" {
		name = getString(event, "name")
	}
	return join(getString(event, mb.ModuleDataKey+".namespace"), name)
}

func containerMetadataIndex(namespace, pod, container string) string {
	return join(namespace, pod, container)
}

func podContainerMetadataKeys(pod *kubernetes.Pod) []string {
	keys := make([]string, 1, 1+len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	keys[0] = containerMetadataIndex(pod.Namespace, pod.Name, "")
	for _, containers := range [][]kubernetes.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for _, container := range containers {
			keys = append(keys, containerMetadataIndex(pod.Namespace, pod.Name, container.Name))
		}
	}
	return keys
}

func join(fields ...string) string {
	return strings.Join(fields, ":")
}

func buildMetadataEnricher(
	watcher kubernetes.Watcher,
	nodeWatcher kubernetes.Watcher,
	namespaceWatcher kubernetes.Watcher,
	update func(map[string]mapstr.M, kubernetes.Resource) []string,
	remove func(map[string]mapstr.M, kubernetes.Resource) []string,
	index func(e mapstr.M) string) *enricher {

	enricher := enricher{
		metadata:           map[string]mapstr.M{},
		metadataTombstones: map[string]metadataTombstone{},
		updateMetadata:     update,
		index:              index,
		watcher:            watcher,
		nodeWatcher:        nodeWatcher,
		namespaceWatcher:   namespaceWatcher,
	}

	watcher.AddEventHandler(kubernetes.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			enricher.Lock()
			defer enricher.Unlock()
			for _, key := range update(enricher.metadata, obj.(kubernetes.Resource)) {
				delete(enricher.metadataTombstones, key)
			}
			enricher.cleanupMetadataTombstones(time.Now())
		},
		UpdateFunc: func(obj interface{}) {
			enricher.Lock()
			defer enricher.Unlock()
			for _, key := range update(enricher.metadata, obj.(kubernetes.Resource)) {
				delete(enricher.metadataTombstones, key)
			}
			enricher.cleanupMetadataTombstones(time.Now())
		},
		DeleteFunc: func(obj interface{}) {
			enricher.Lock()
			defer enricher.Unlock()
			now := time.Now()
			for _, key := range remove(enricher.metadata, obj.(kubernetes.Resource)) {
				if meta := enricher.metadata[key]; meta != nil {
					if enricher.deletionGracePeriod > 0 {
						expiresAt := now.Add(enricher.deletionGracePeriod)
						enricher.metadataTombstones[key] = metadataTombstone{meta: meta, expiresAt: expiresAt}
						if enricher.nextMetadataCleanup.IsZero() || expiresAt.Before(enricher.nextMetadataCleanup) {
							enricher.nextMetadataCleanup = expiresAt
						}
					}
					delete(enricher.metadata, key)
				}
			}
			enricher.cleanupMetadataTombstones(now)
		},
	})

	return &enricher
}

func (m *enricher) cleanupMetadataTombstones(now time.Time) {
	if now.Before(m.nextMetadataCleanup) {
		return
	}
	m.nextMetadataCleanup = time.Time{}
	for key, tombstone := range m.metadataTombstones {
		if !now.Before(tombstone.expiresAt) {
			delete(m.metadataTombstones, key)
		} else if m.nextMetadataCleanup.IsZero() || tombstone.expiresAt.Before(m.nextMetadataCleanup) {
			m.nextMetadataCleanup = tombstone.expiresAt
		}
	}
}

func (m *enricher) Start() {
	m.watchersStartedLock.Lock()
	defer m.watchersStartedLock.Unlock()
	if !m.watchersStarted {
		for _, watcher := range m.workloadWatchers {
			if err := watcher.Start(); err != nil {
				logp.Warn("Error starting workload watcher: %s", err)
			}
		}
		if m.nodeWatcher != nil {
			if err := m.nodeWatcher.Start(); err != nil {
				logp.Warn("Error starting node watcher: %s", err)
			} else if m.syncNodeMetrics != nil {
				m.syncNodeMetrics()
			}
		}

		if m.namespaceWatcher != nil {
			if err := m.namespaceWatcher.Start(); err != nil {
				logp.Warn("Error starting namespace watcher: %s", err)
			}
		}

		err := m.watcher.Start()
		if err != nil {
			logp.Warn("Error starting Kubernetes watcher: %s", err)
		} else {
			m.initializeMetadataFromStore()
		}
		m.watchersStarted = true
	}
}

func (m *enricher) initializeMetadataFromStore() {
	store := m.watcher.Store()
	if store == nil || m.updateMetadata == nil {
		return
	}

	m.Lock()
	defer m.Unlock()
	for _, key := range store.ListKeys() {
		object, exists, err := store.GetByKey(key)
		if err != nil || !exists {
			continue
		}
		resource, ok := object.(kubernetes.Resource)
		if !ok {
			continue
		}
		for _, key := range m.updateMetadata(m.metadata, resource) {
			delete(m.metadataTombstones, key)
		}
	}
	m.cleanupMetadataTombstones(time.Now())
}

func (m *enricher) Stop() {
	m.watchersStartedLock.Lock()
	defer m.watchersStartedLock.Unlock()
	m.watcher.Stop()
	for _, watcher := range m.workloadWatchers {
		watcher.Stop()
	}

	if m.namespaceWatcher != nil {
		m.namespaceWatcher.Stop()
	}

	if m.nodeWatcher != nil {
		m.nodeWatcher.Stop()
	}

	m.watchersStarted = false
}

func (m *enricher) Enrich(events []mapstr.M) {
	m.enrich(events, nil, false)
}

func (m *enricher) EnrichProjected(events []mapstr.M, required func(string) bool) {
	m.enrich(events, required, false)
}

func (m *enricher) EnrichSharedMetadata(events []mapstr.M) {
	m.enrich(events, nil, true)
}

func (m *enricher) enrich(events []mapstr.M, required func(string) bool, shared bool) {
	m.Lock()
	now := time.Now()
	m.cleanupMetadataTombstones(now)
	m.Unlock()
	for _, event := range events {
		key := m.index(event)
		m.RLock()
		meta := m.metadata[key]
		if meta == nil {
			if tombstone, ok := m.metadataTombstones[key]; ok && now.Before(tombstone.expiresAt) {
				meta = tombstone.meta
			}
		}
		m.RUnlock()
		if meta != nil {
			if shared {
				meta = snapshotEventMetadata(meta)
			} else if required == nil {
				meta = meta.Clone()
			} else {
				meta = cloneProjectedMetadata(meta, "", false, required).(mapstr.M)
			}
			k8s, err := meta.GetValue("kubernetes")
			if err != nil {
				continue
			}
			k8sMeta, ok := k8s.(mapstr.M)
			if !ok {
				continue
			}

			if m.isPod {
				// apply pod meta at metricset level
				if podMeta, ok := k8sMeta["pod"].(mapstr.M); ok {
					event.DeepUpdate(podMeta)
				}

				// don't apply pod metadata to module level
				delete(k8sMeta, "pod")
			}
			ecsMeta := meta
			err = ecsMeta.Delete("kubernetes")
			if err != nil {
				logp.Debug("kubernetes", "Failed to delete field '%s': %s", "kubernetes", err)
			}

			event.DeepUpdate(mapstr.M{
				mb.ModuleDataKey: k8sMeta,
				"meta":           ecsMeta,
			})
		}
	}
}

type nilEnricher struct{}

func (*nilEnricher) Start()            {}
func (*nilEnricher) Stop()             {}
func (*nilEnricher) Enrich([]mapstr.M) {}

func CreateEvent(event mapstr.M, namespace string) (mb.Event, error) {
	var moduleFieldsMapStr mapstr.M
	moduleFields, ok := event[mb.ModuleDataKey]
	var err error
	if ok {
		moduleFieldsMapStr, ok = moduleFields.(mapstr.M)
		if !ok {
			err = fmt.Errorf("error trying to convert '%s' from event to mapstr.M", mb.ModuleDataKey)
		}
	}
	delete(event, mb.ModuleDataKey)

	e := mb.Event{
		MetricSetFields: event,
		ModuleFields:    moduleFieldsMapStr,
		Namespace:       namespace,
	}

	// add root-level fields like ECS fields
	var metaFieldsMapStr mapstr.M
	metaFields, ok := event["meta"]
	if ok {
		metaFieldsMapStr, ok = metaFields.(mapstr.M)
		if !ok {
			err = fmt.Errorf("error trying to convert '%s' from event to mapstr.M", "meta")
		}
		delete(event, "meta")
		if len(metaFieldsMapStr) > 0 {
			e.RootFields = metaFieldsMapStr
		}
	}
	return e, err
}

func GetClusterECSMeta(cfg *conf.C, client k8sclient.Interface, logger *logp.Logger) (mapstr.M, error) {
	clusterInfo, err := metadata.GetKubernetesClusterIdentifier(cfg, client)
	if err != nil {
		return nil, fmt.Errorf("fail to get kubernetes cluster metadata: %w", err)
	}
	ecsClusterMeta := mapstr.M{}
	if clusterInfo.URL != "" {
		kubernetes2.ShouldPut(ecsClusterMeta, "orchestrator.cluster.url", clusterInfo.URL, logger)
	}
	if clusterInfo.Name != "" {
		kubernetes2.ShouldPut(ecsClusterMeta, "orchestrator.cluster.name", clusterInfo.Name, logger)
	}
	return ecsClusterMeta, nil
}

// AddClusterECSMeta adds ECS orchestrator fields
func AddClusterECSMeta(base mb.BaseMetricSet) mapstr.M {
	config, err := GetValidatedConfig(base)
	if err != nil {
		logp.Info("could not retrieve validated config")
		return nil
	}
	client, err := kubernetes.GetKubernetesClient(config.KubeConfig, config.KubeClientOptions)
	if err != nil {
		logp.Err("fail to get kubernetes client: %s", err)
		return nil
	}
	cfg, _ := conf.NewConfigFrom(&config)
	ecsClusterMeta, err := GetClusterECSMeta(cfg, client, base.Logger())
	if err != nil {
		logp.Info("could not retrieve cluster metadata: %s", err)
		return nil
	}
	return ecsClusterMeta
}
