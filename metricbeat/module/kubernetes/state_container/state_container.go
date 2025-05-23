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

package state_container

import (
	"fmt"
	"strings"

	"github.com/elastic/beats/v7/libbeat/autodiscover/providers/kubernetes"
	"github.com/elastic/beats/v7/metricbeat/helper/easyops"
	p "github.com/elastic/beats/v7/metricbeat/helper/prometheus"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/mb/parse"
	k8smod "github.com/elastic/beats/v7/metricbeat/module/kubernetes"
	"github.com/elastic/beats/v7/metricbeat/module/kubernetes/util"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	defaultScheme = "http"
	defaultPath   = "/metrics"
)

var (
	hostParser = parse.URLHostParserBuilder{
		DefaultScheme: defaultScheme,
		DefaultPath:   defaultPath,
	}.Build()

	// Mapping of state metrics
	mapping = &p.MetricsMapping{
		Metrics: map[string]p.MetricMap{
			"kube_pod_info":           p.InfoMetric(),
			"kube_pod_container_info": p.InfoMetric(),
			"kube_pod_container_resource_requests": p.Metric("", p.OpFilterMap(
				"resource", map[string]string{
					"cpu":    "cpu.request.cores",
					"memory": "memory.request.bytes",
				},
			)),
			"kube_pod_container_resource_limits": p.Metric("", p.OpFilterMap(
				"resource", map[string]string{
					"cpu":    "cpu.limit.cores",
					"memory": "memory.limit.bytes",
				},
			)),
			"kube_pod_container_resource_limits_cpu_cores":      p.Metric("cpu.limit.cores"),
			"kube_pod_container_resource_requests_cpu_cores":    p.Metric("cpu.request.cores"),
			"kube_pod_container_resource_limits_memory_bytes":   p.Metric("memory.limit.bytes"),
			"kube_pod_container_resource_requests_memory_bytes": p.Metric("memory.request.bytes"),
			"kube_pod_container_status_ready":                   p.BooleanMetric("status.ready"),
			"kube_pod_container_status_restarts":                p.Metric("status.restarts"),
			"kube_pod_container_status_restarts_total":          p.Metric("status.restarts"),
			"kube_pod_container_status_running":                 p.KeywordMetric("status.phase", "running"),
			"kube_pod_container_status_terminated":              p.KeywordMetric("status.phase", "terminated"),
			"kube_pod_container_status_waiting":                 p.KeywordMetric("status.phase", "waiting"),
			"kube_pod_container_status_terminated_reason":       p.LabelMetric("status.reason", "reason"),
			"kube_pod_container_status_waiting_reason":          p.LabelMetric("status.reason", "reason"),
			"kube_pod_container_status_last_terminated_reason":  p.LabelMetric("status.last_terminated_reason", "reason"),
		},

		AggregateMetrics: []easyops.AggregateMetricMap{
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "pod.cpu.request.cores",
				OriginMetrics: []string{"cpu.request.cores"},
				GroupKeys:     []string{"_module.namespace", "_module.pod.name", "_module.node.name"},
			},
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "pod.memory.request.bytes",
				OriginMetrics: []string{"memory.request.bytes"},
				GroupKeys:     []string{"_module.namespace", "_module.pod.name", "_module.node.name"},
			},
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "pod.memory.limit.bytes",
				OriginMetrics: []string{"memory.limit.bytes"},
				GroupKeys:     []string{"_module.namespace", "_module.pod.name"},
			},
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "pod.status.restarts",
				OriginMetrics: []string{"status.restarts"},
				GroupKeys:     []string{"_module.namespace", "_module.pod.name"},
			},
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "node.cpu.request.cores",
				OriginMetrics: []string{"pod.cpu.request.cores"},
				GroupKeys:     []string{"_module.node.name"},
			},
			{
				Type:          easyops.AggregateTypeSum,
				Field:         "node.memory.request.bytes",
				OriginMetrics: []string{"pod.memory.request.bytes"},
				GroupKeys:     []string{"_module.node.name"},
			},
		},

		Labels: map[string]p.LabelMap{
			"pod":       p.KeyLabel(mb.ModuleDataKey + ".pod.name"),
			"container": p.KeyLabel("name"),
			"namespace": p.KeyLabel(mb.ModuleDataKey + ".namespace"),

			"node":         p.Label(mb.ModuleDataKey + ".node.name"),
			"container_id": p.Label("id"),
			"image":        p.Label("image"),
		},
	}
)

// init registers the MetricSet with the central registry.
// The New method will be called after the setup of the module and before starting to fetch data
func init() {
	mb.Registry.MustAddMetricSet("kubernetes", "state_container", New,
		mb.WithHostParser(hostParser),
	)
}

// MetricSet type defines all fields of the MetricSet
// As a minimum it must inherit the mb.BaseMetricSet fields, but can be extended with
// additional entries. These variables can be used to persist data or configuration between
// multiple fetch calls.
type MetricSet struct {
	mb.BaseMetricSet
	prometheus p.Prometheus
	enricher   util.Enricher
	mod        k8smod.Module
}

// New create a new instance of the MetricSet
// Part of new is also setting up the configuration by processing additional
// configuration entries if needed.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	prometheus, err := p.NewPrometheusClient(base)
	if err != nil {
		return nil, err
	}
	mod, ok := base.Module().(k8smod.Module)
	if !ok {
		return nil, fmt.Errorf("must be child of kubernetes module")
	}
	return &MetricSet{
		BaseMetricSet: base,
		prometheus:    prometheus,
		enricher:      util.NewContainerMetadataEnricher(base, mod.GetMetricsRepo(), false),
		mod:           mod,
	}, nil
}

// Fetch methods implements the data gathering and data conversion to the right
// format. It publishes the event which is then forwarded to the output. In case
// of an error set the Error field of mb.Event or simply call report.Error().
func (m *MetricSet) Fetch(reporter mb.ReporterV2) error {
	m.enricher.Start()

	families, err := m.mod.GetStateMetricsFamilies(m.prometheus)
	if err != nil {
		return fmt.Errorf("error getting families: %w", err)
	}
	events, err := m.prometheus.ProcessMetrics(families, mapping)
	if err != nil {
		return fmt.Errorf("error getting event: %w", err)
	}

	m.enricher.Enrich(events)

	for _, event := range events {
		// applying ECS to kubernetes.container.id in the form <container.runtime>://<container.id>
		// copy to ECS fields the kubernetes.container.image, kubernetes.container.name
		containerFields := mapstr.M{}
		if containerID, ok := event["id"]; ok {
			// we don't expect errors here, but if any we would obtain an
			// empty string
			cID, ok := (containerID).(string)
			if !ok {
				m.Logger().Debugf("Error while casting containerID: %s", ok)
			}
			split := strings.Index(cID, "://")
			if split != -1 {
				kubernetes.ShouldPut(containerFields, "runtime", cID[:split], m.Logger())

				kubernetes.ShouldPut(containerFields, "id", cID[split+3:], m.Logger())
			}
		}
		if containerImage, ok := event["image"]; ok {
			cImage, ok := (containerImage).(string)
			if !ok {
				m.Logger().Debugf("Error while casting containerImage: %s", ok)
			}

			kubernetes.ShouldPut(containerFields, "image.name", cImage, m.Logger())
			// remove kubernetes.container.image field as value is the same as ECS container.image.name field
			kubernetes.ShouldDelete(event, "image", m.Logger())
		}

		e, err := util.CreateEvent(event, "kubernetes.state_container")
		if err != nil {
			m.Logger().Error(err)
		}

		if len(containerFields) > 0 {
			if e.RootFields != nil {
				e.RootFields.DeepUpdate(mapstr.M{
					"container": containerFields,
				})
			} else {
				e.RootFields = mapstr.M{
					"container": containerFields,
				}
			}
		}

		util.EnrichWorkloadInfo(e.ModuleFields, "pod.name", e)

		if reported := reporter.Event(e); !reported {
			return nil
		}
	}

	return nil
}

// Close stops this metricset
func (m *MetricSet) Close() error {
	m.enricher.Stop()
	return nil
}
