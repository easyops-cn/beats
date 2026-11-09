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

package kubernetes

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mitchellh/hashstructure"
	dto "github.com/prometheus/client_model/go"

	"github.com/elastic/beats/v7/metricbeat/helper"
	p "github.com/elastic/beats/v7/metricbeat/helper/prometheus"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/module/kubernetes/util"
)

func init() {
	// Register the ModuleFactory function for the "kubernetes" module.
	if err := mb.Registry.AddModule("kubernetes", ModuleBuilder()); err != nil {
		panic(err)
	}
}

type Module interface {
	mb.Module
	GetStateMetricsFamilies(prometheus p.Prometheus) ([]*dto.MetricFamily, error)
	GetStateMetricsFamiliesFor(prometheus p.Prometheus, mapping *p.MetricsMapping) ([]*dto.MetricFamily, error)
	GetKubeletStats(http *helper.HTTP) ([]byte, error)
	GetKubeletSummary(http *helper.HTTP) (*Summary, error)
	GetMetricsRepo() *util.MetricsRepo
}

type familiesCache struct {
	lock                sync.Mutex
	sharedFamilies      []*dto.MetricFamily
	byName              map[string]*dto.MetricFamily
	lastFetchErr        error
	lastFetchTimestamp  time.Time
	lastAccessTimestamp time.Time
}

type kubeStateMetricsCache struct {
	cacheMap map[uint64]*familiesCache
	lock     sync.Mutex
	pinned   bool
}

func (c *kubeStateMetricsCache) getCacheMapEntry(hash uint64) *familiesCache {
	now := time.Now()
	if _, ok := c.cacheMap[hash]; !ok {
		if !c.pinned {
			var oldestKey uint64
			var oldest time.Time
			for key, entry := range c.cacheMap {
				if now.Sub(entry.lastAccessTimestamp) > collectionCacheIdleTTL {
					delete(c.cacheMap, key)
				} else if oldest.IsZero() || entry.lastAccessTimestamp.Before(oldest) {
					oldestKey, oldest = key, entry.lastAccessTimestamp
				}
			}
			if len(c.cacheMap) >= collectionCacheMaxEntries {
				delete(c.cacheMap, oldestKey)
			}
		}
		c.cacheMap[hash] = &familiesCache{}
	}
	c.cacheMap[hash].lastAccessTimestamp = now
	return c.cacheMap[hash]
}

type statsCache struct {
	lock                sync.Mutex
	endpoint            string
	sharedSummary       *Summary
	lastFetchErr        error
	lastFetchTimestamp  time.Time
	lastAccessTimestamp time.Time
}

type kubeletStatsCache struct {
	cacheMap map[uint64]*statsCache
	lock     sync.Mutex
	pinned   bool
}

func (c *kubeletStatsCache) getCacheMapEntry(hash uint64) *statsCache {
	now := time.Now()
	if _, ok := c.cacheMap[hash]; !ok {
		if !c.pinned {
			var oldestKey uint64
			var oldest time.Time
			for key, entry := range c.cacheMap {
				if now.Sub(entry.lastAccessTimestamp) > collectionCacheIdleTTL {
					delete(c.cacheMap, key)
				} else if oldest.IsZero() || entry.lastAccessTimestamp.Before(oldest) {
					oldestKey, oldest = key, entry.lastAccessTimestamp
				}
			}
			if len(c.cacheMap) >= collectionCacheMaxEntries {
				delete(c.cacheMap, oldestKey)
			}
		}
		c.cacheMap[hash] = &statsCache{}
	}
	c.cacheMap[hash].lastAccessTimestamp = now
	return c.cacheMap[hash]
}

const (
	collectionCacheMaxEntries = 256
	collectionCacheIdleTTL    = 10 * time.Minute
)

type module struct {
	mb.BaseModule

	kubeStateMetricsCache *kubeStateMetricsCache
	kubeletStatsCache     *kubeletStatsCache
	metricsRepo           *util.MetricsRepo
	cacheHash             uint64
	maxResponseBytes      int64
	stateFamilies         map[string]struct{}
	compactMappings       []*p.MetricsMapping
	compactState          map[string]*compactStateCache
}

var stateMetricMappings sync.Map

func RegisterStateMetricsMapping(name string, mapping *p.MetricsMapping) {
	stateMetricMappings.Store(name, mapping)
}

func stateFamiliesFor(metricsets []string) map[string]struct{} {
	families := make(map[string]struct{})
	for _, name := range metricsets {
		if !strings.HasPrefix(name, "state_") {
			continue
		}
		mapping, exists := stateMetricMappings.Load(name)
		if !exists {
			return nil
		}
		for family := range mapping.(*p.MetricsMapping).Metrics {
			families[family] = struct{}{}
		}
	}
	if len(families) == 0 {
		return nil
	}
	return families
}

func ModuleBuilder() func(base mb.BaseModule) (mb.Module, error) {
	return func(base mb.BaseModule) (mb.Module, error) {
		limits := struct {
			MaxResponseBytes int64 `config:"max_response_bytes"`
		}{MaxResponseBytes: 64 << 20}
		if err := base.UnpackConfig(&limits); err != nil {
			return nil, err
		}
		if limits.MaxResponseBytes <= 0 || limits.MaxResponseBytes > 1<<30 {
			return nil, fmt.Errorf("max_response_bytes must be between 1 and 1073741824")
		}
		hash, err := generateCacheHash(base.Config().Hosts)
		if err != nil {
			return nil, fmt.Errorf("error generating cache hash for kubeStateMetricsCache: %w", err)
		}

		m := module{
			BaseModule:            base,
			kubeStateMetricsCache: &kubeStateMetricsCache{cacheMap: make(map[uint64]*familiesCache)},
			kubeletStatsCache:     &kubeletStatsCache{cacheMap: make(map[uint64]*statsCache)},
			metricsRepo:           util.NewMetricsRepo(),
			cacheHash:             hash,
			maxResponseBytes:      limits.MaxResponseBytes,
			stateFamilies:         stateFamiliesFor(base.Config().MetricSets),
		}
		return &m, nil
	}
}

func (m *module) GetStateMetricsFamilies(prometheus p.Prometheus) ([]*dto.MetricFamily, error) {
	entry, err := m.getStateMetricsCache(prometheus, nil)
	if err != nil {
		return nil, err
	}
	return entry.sharedFamilies, nil
}

func (m *module) GetStateMetricsFamiliesFor(prometheus p.Prometheus, mapping *p.MetricsMapping) ([]*dto.MetricFamily, error) {
	entry, err := m.getStateMetricsCache(prometheus, m.stateFamilies)
	if err != nil {
		return nil, err
	}
	families := make([]*dto.MetricFamily, 0, len(mapping.Metrics))
	for name := range mapping.Metrics {
		if family := entry.byName[name]; family != nil {
			families = append(families, family)
		}
	}
	return families, nil
}

func (m *module) getStateMetricsCache(prometheus p.Prometheus, selected map[string]struct{}) (*familiesCache, error) {
	endpoint := ""
	if source, ok := prometheus.(interface{ Endpoint() string }); ok {
		endpoint = source.Endpoint()
	}
	if selected != nil {
		endpoint += "\x00selected"
	}
	key, err := generateURLCacheHash(m.cacheHash, endpoint)
	if err != nil {
		return nil, err
	}
	m.kubeStateMetricsCache.lock.Lock()
	entry := m.kubeStateMetricsCache.getCacheMapEntry(key)
	pinned := m.kubeStateMetricsCache.pinned
	m.kubeStateMetricsCache.lock.Unlock()
	entry.lock.Lock()
	defer entry.lock.Unlock()
	now := time.Now()
	if entry.lastFetchTimestamp.IsZero() || (!pinned && now.Sub(entry.lastFetchTimestamp) > m.Config().Period) {
		var families []*dto.MetricFamily
		var fetchErr error
		if filtered, ok := prometheus.(interface {
			GetFamiliesFor(map[string]struct{}) ([]*dto.MetricFamily, error)
		}); ok && selected != nil {
			families, fetchErr = filtered.GetFamiliesFor(selected)
		} else {
			families, fetchErr = prometheus.GetFamilies()
		}
		entry.sharedFamilies = families
		entry.lastFetchErr = fetchErr
		entry.byName = make(map[string]*dto.MetricFamily, len(families))
		for _, family := range families {
			entry.byName[family.GetName()] = family
		}
		entry.lastFetchTimestamp = now
	}
	return &familiesCache{sharedFamilies: entry.sharedFamilies, byName: entry.byName}, entry.lastFetchErr
}

func (m *module) GetKubeletStats(http *helper.HTTP) ([]byte, error) {
	summary, err := m.GetKubeletSummary(http)
	if err != nil {
		return nil, err
	}

	// Convert Summary back to JSON for backward compatibility
	return json.Marshal(summary)
}

// GetKubeletSummary returns the parsed kubernetes.Summary from kubelet stats endpoint
func (m *module) GetKubeletSummary(http *helper.HTTP) (*Summary, error) {
	now := time.Now()

	// Generate cache key based on both module hash and HTTP URL to ensure
	// different URLs have different cache entries
	url := http.GetURI()
	cacheKey, err := generateURLCacheHash(m.cacheHash, url)
	if err != nil {
		return nil, fmt.Errorf("error generating cache key for URL %s: %w", url, err)
	}

	m.kubeletStatsCache.lock.Lock()
	statsCache := m.kubeletStatsCache.getCacheMapEntry(cacheKey)
	statsCache.endpoint = url
	pinned := m.kubeletStatsCache.pinned
	m.kubeletStatsCache.lock.Unlock()
	statsCache.lock.Lock()
	defer statsCache.lock.Unlock()

	if statsCache.lastFetchTimestamp.IsZero() || (!pinned && now.Sub(statsCache.lastFetchTimestamp) > m.Config().Period) {
		statsCache.sharedSummary = nil
		// Fetch raw data from HTTP endpoint
		rawData, fetchErr := http.FetchContentWithLimit(m.maxResponseBytes)
		if fetchErr != nil {
			statsCache.lastFetchErr = fetchErr
			statsCache.lastFetchTimestamp = now
			return nil, fetchErr
		}

		// Parse JSON into Summary structure
		var summary Summary
		if parseErr := json.Unmarshal(rawData, &summary); parseErr != nil {
			statsCache.lastFetchErr = fmt.Errorf("cannot unmarshal json response: %w", parseErr)
			statsCache.lastFetchTimestamp = now
			return nil, statsCache.lastFetchErr
		}

		// Cache the parsed structure
		statsCache.sharedSummary = &summary
		statsCache.lastFetchErr = nil
		statsCache.lastFetchTimestamp = now
	}

	return statsCache.sharedSummary, statsCache.lastFetchErr
}

func (m *module) BeginCollection() {
	m.resetCollection(true)
}

func (m *module) EndCollection() {
	m.resetCollection(false)
}

func (m *module) resetCollection(pinned bool) {
	m.kubeStateMetricsCache.lock.Lock()
	m.compactState = nil
	m.compactMappings = nil
	m.kubeStateMetricsCache.cacheMap = make(map[uint64]*familiesCache)
	m.kubeStateMetricsCache.pinned = pinned
	m.kubeStateMetricsCache.lock.Unlock()
	m.kubeletStatsCache.lock.Lock()
	m.kubeletStatsCache.cacheMap = make(map[uint64]*statsCache)
	m.kubeletStatsCache.pinned = pinned
	m.kubeletStatsCache.lock.Unlock()
}

func generateCacheHash(host []string) (uint64, error) {
	id, err := hashstructure.Hash(host, nil)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// generateURLCacheHash generates a cache key based on module hash and HTTP URL
func generateURLCacheHash(moduleHash uint64, url string) (uint64, error) {
	cacheData := struct {
		ModuleHash uint64
		URL        string
	}{
		ModuleHash: moduleHash,
		URL:        url,
	}

	id, err := hashstructure.Hash(cacheData, nil)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (m *module) GetMetricsRepo() *util.MetricsRepo {
	return m.metricsRepo
}
