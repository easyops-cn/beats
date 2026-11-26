package util

import (
	"fmt"
	"sync"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
)

type sharedEnricher struct {
	Enricher
	refs int
}

type enricherLease struct {
	*sharedEnricher
	repo     *MetricsRepo
	key      string
	stopOnce sync.Once
}

func NewResourceMetadataEnricher(base mb.BaseMetricSet, resource kubernetes.Resource, repo *MetricsRepo, nodeScope bool) Enricher {
	return acquireMetadataEnricher(base, fmt.Sprintf("resource:%T", resource), repo, nodeScope, func() Enricher {
		return newResourceMetadataEnricher(base, resource, repo, nodeScope)
	})
}

func NewContainerMetadataEnricher(base mb.BaseMetricSet, repo *MetricsRepo, nodeScope bool) Enricher {
	return acquireMetadataEnricher(base, "container", repo, nodeScope, func() Enricher {
		return newContainerMetadataEnricher(base, repo, nodeScope)
	})
}

func acquireMetadataEnricher(base mb.BaseMetricSet, resource string, repo *MetricsRepo, nodeScope bool, create func() Enricher) Enricher {
	config, err := GetValidatedConfig(base)
	if err != nil {
		return &nilEnricher{}
	}
	node := ""
	if nodeScope {
		node = config.Node
	}
	key := fmt.Sprintf("%s:%q:%q:%t", resource, config.Namespace, node, nodeScope)
	repo.enricherMu.Lock()
	defer repo.enricherMu.Unlock()
	if repo.enrichers == nil {
		repo.enrichers = make(map[string]*sharedEnricher)
	}
	shared := repo.enrichers[key]
	if shared == nil {
		shared = &sharedEnricher{Enricher: create()}
		repo.enrichers[key] = shared
	}
	shared.refs++
	return &enricherLease{sharedEnricher: shared, repo: repo, key: key}
}

func (lease *enricherLease) Stop() {
	lease.stopOnce.Do(func() {
		var stop Enricher
		lease.repo.enricherMu.Lock()
		lease.refs--
		if lease.refs == 0 {
			stop = lease.Enricher
			delete(lease.repo.enrichers, lease.key)
		}
		lease.repo.enricherMu.Unlock()
		// Stopping a watcher can block while goroutines drain. Do not hold the
		// repository lock during that operation, otherwise unrelated metricsets
		// cannot acquire or release their shared enrichers.
		if stop != nil {
			stop.Stop()
		}
	})
}
