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

package container

import (
	"fmt"
	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/beats/v7/metricbeat/helper"
	"github.com/elastic/beats/v7/metricbeat/helper/easyops"
	"github.com/elastic/beats/v7/metricbeat/helper/prometheus"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/mb/parse"
	k8smod "github.com/elastic/beats/v7/metricbeat/module/kubernetes"
	"github.com/elastic/beats/v7/metricbeat/module/kubernetes/util"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	defaultScheme = "http"
	defaultPath   = "/stats/summary"
)

var (
	hostParser = parse.URLHostParserBuilder{
		DefaultScheme: defaultScheme,
		DefaultPath:   defaultPath,
	}.Build()

	mapping = &prometheus.MetricsMapping{
		AggregateMetrics: []easyops.AggregateMetricMap{
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "pod.memory.allocated.bytes",
				OriginMetrics: []string{"memory.available.bytes", "memory.usage.bytes"},
				GroupKeys:     []string{"_module.namespace", "_module.pod.name"},
			},
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "pod.memory.usage.bytes",
				OriginMetrics: []string{"memory.usage.bytes"},
				GroupKeys:     []string{"_module.namespace", "_module.pod.name"},
			},
			{
				Type:          easyops.AggregateTypeDiv,
				Field:         "pod.memory.usage.pct",
				OriginMetrics: []string{"pod.memory.usage.bytes", "pod.memory.allocated.bytes"},
				GroupKeys:     []string{"_module.namespace", "_module.pod.name"},
			},
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "node.cpu.usage.pct",
				OriginMetrics: []string{"cpu.usage.node.pct"},
				GroupKeys:     []string{"_module.node.name"},
			},
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "pod.rootfs.used.bytes",
				OriginMetrics: []string{"rootfs.used.bytes"},
				GroupKeys:     []string{"_module.namespace", "_module.pod.name"},
			},
		},
	}

	logger = logp.NewLogger("kubernetes.container")
)

// init registers the MetricSet with the central registry.
// The New method will be called after the setup of the module and before starting to fetch data
func init() {
	mb.Registry.MustAddMetricSet("kubernetes", "container", New,
		mb.WithHostParser(hostParser),
		mb.DefaultMetricSet(),
	)
}

// MetricSet type defines all fields of the MetricSet
// As a minimum it must inherit the mb.BaseMetricSet fields, but can be extended with
// additional entries. These variables can be used to persist data or configuration between
// multiple fetch calls.
type MetricSet struct {
	mb.BaseMetricSet
	http     *helper.HTTP
	enricher util.Enricher
	mod      k8smod.Module
}

// New create a new instance of the MetricSet
// Part of new is also setting up the configuration by processing additional
// configuration entries if needed.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	http, err := helper.NewHTTP(base)
	if err != nil {
		return nil, err
	}
	mod, ok := base.Module().(k8smod.Module)
	if !ok {
		return nil, fmt.Errorf("must be child of kubernetes module")
	}
	return &MetricSet{
		BaseMetricSet: base,
		http:          http,
		enricher:      util.NewContainerMetadataEnricher(base, mod.GetMetricsRepo(), true),
		mod:           mod,
	}, nil
}

// Fetch methods implements the data gathering and data conversion to the right
// format. It publishes the event which is then forwarded to the output. In case
// of an error set the Error field of mb.Event or simply call report.Error().
func (m *MetricSet) Fetch(reporter mb.ReporterV2) {
	m.enricher.Start()

	summary, err := m.mod.GetKubeletSummary(m.http)
	if err != nil {
		m.Logger().Error(err)
		reporter.Error(err)
		return
	}

	events, err := eventMapping(summary, m.mod.GetMetricsRepo(), m.Logger(), mapping)
	if err != nil {
		m.Logger().Error(err)
		reporter.Error(err)
		return
	}

	m.enricher.Enrich(events)

	for _, event := range events {

		e, err := util.CreateEvent(event, "kubernetes.container")
		if err != nil {
			m.Logger().Error(err)
		}
		// Enrich event with container ECS fields
		containerEcsFields := ecsfields(event, m.Logger())
		if len(containerEcsFields) != 0 {
			if e.RootFields != nil {
				e.RootFields.DeepUpdate(mapstr.M{
					"container": containerEcsFields,
				})
			} else {
				e.RootFields = mapstr.M{
					"container": containerEcsFields,
				}
			}
		}

		util.EnrichWorkloadInfo(e.ModuleFields, "pod.name", e)

		if reported := reporter.Event(e); !reported {
			m.Logger().Debug("error trying to emit event")
			return
		}
	}
}

// Close stops this metricset
func (m *MetricSet) Close() error {
	m.enricher.Stop()
	return nil
}
