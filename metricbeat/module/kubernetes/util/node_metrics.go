package util

import (
	"sync"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
)

func setNodeCapacity(repo *MetricsRepo, node *kubernetes.Node) {
	metrics := NewNodeMetrics()
	if cpu, exists := node.Status.Capacity["cpu"]; exists {
		metrics.CoresAllocatable = NewFloat64Metric(float64(cpu.MilliValue()) / 1000)
	}
	if memory, exists := node.Status.Capacity["memory"]; exists {
		metrics.MemoryAllocatable = NewFloat64Metric(float64(memory.Value()))
	}
	store, _ := repo.AddNodeStore(node.Name)
	store.SetNodeMetrics(metrics)
}

func trackNodeMetrics(watcher kubernetes.Watcher, repo *MetricsRepo) func() {
	if watcher == nil {
		return nil
	}
	var mutex sync.Mutex
	update := func(object interface{}) {
		if node, ok := object.(*kubernetes.Node); ok {
			mutex.Lock()
			setNodeCapacity(repo, node)
			mutex.Unlock()
		}
	}
	watcher.AddEventHandler(kubernetes.ResourceEventHandlerFuncs{AddFunc: update, UpdateFunc: update, DeleteFunc: func(object interface{}) {
		if node, ok := object.(*kubernetes.Node); ok {
			mutex.Lock()
			repo.GetNodeStore(node.Name).SetNodeMetrics(NewNodeMetrics())
			mutex.Unlock()
		}
	}})
	return func() {
		mutex.Lock()
		defer mutex.Unlock()
		if store := watcher.Store(); store != nil {
			for _, object := range store.List() {
				if node, ok := object.(*kubernetes.Node); ok {
					setNodeCapacity(repo, node)
				}
			}
		}
	}
}
