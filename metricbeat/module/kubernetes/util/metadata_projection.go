package util

import (
	"reflect"
	"strings"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func EnrichForReporter(enricher Enricher, events []mapstr.M, reporter mb.ReporterV2) {
	readonly, optedIn := reporter.(interface{ SharedKubernetesMetadataEnabled() bool })
	shared, supportsShared := enricher.(interface{ EnrichSharedMetadata([]mapstr.M) })
	if optedIn && supportsShared && readonly.SharedKubernetesMetadataEnabled() {
		shared.EnrichSharedMetadata(events)
		return
	}
	projection, selected := reporter.(interface {
		MetadataFieldRequired(string) bool
		MetadataProjectionEnabled() bool
	})
	projected, supported := enricher.(interface {
		EnrichProjected([]mapstr.M, func(string) bool)
	})
	if selected && supported && projection.MetadataProjectionEnabled() {
		projected.EnrichProjected(events, projection.MetadataFieldRequired)
	} else {
		enricher.Enrich(events)
	}
}

func (lease *enricherLease) EnrichSharedMetadata(events []mapstr.M) {
	if shared, ok := lease.Enricher.(interface{ EnrichSharedMetadata([]mapstr.M) }); ok {
		shared.EnrichSharedMetadata(events)
	} else {
		lease.Enricher.Enrich(events)
	}
}

func (lease *enricherLease) EnrichProjected(events []mapstr.M, required func(string) bool) {
	if projected, ok := lease.Enricher.(interface {
		EnrichProjected([]mapstr.M, func(string) bool)
	}); ok {
		projected.EnrichProjected(events, required)
	} else {
		lease.Enricher.Enrich(events)
	}
}

func cloneProjectedMetadata(value interface{}, prefix string, restricted bool, required func(string) bool) interface{} {
	cloneMap := func(source mapstr.M) mapstr.M {
		capacity := len(source)
		if restricted {
			capacity = 0
		}
		output := make(mapstr.M, capacity)
		for key, child := range source {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			childRestricted := restricted || key == "labels" || key == "annotations" || strings.HasSuffix(key, "_labels") || strings.HasSuffix(key, "_annotations")
			if childRestricted && !required(path) {
				continue
			}
			output[key] = cloneProjectedMetadata(child, path, childRestricted, required)
		}
		return output
	}
	switch typed := value.(type) {
	case mapstr.M:
		return cloneMap(typed)
	case map[string]interface{}:
		return cloneMap(mapstr.M(typed))
	case []interface{}:
		result := make([]interface{}, len(typed))
		for index, child := range typed {
			result[index] = cloneProjectedMetadata(child, prefix, restricted, required)
		}
		return result
	default:
		kind := reflect.ValueOf(value).Kind()
		if kind == reflect.Map || kind == reflect.Slice || kind == reflect.Array {
			return mapstr.M{"value": value}.Clone()["value"]
		}
		return value
	}
}
