package util

import (
	"testing"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func TestExtractWorkloadName(t *testing.T) {
	tests := []struct {
		name    string
		podName string
		want    string
	}{
		{name: "deployment", podName: "checkout-7d8f9c6b4f-abc12", want: "checkout"},
		{name: "statefulset", podName: "mysql-3", want: "mysql"},
		{name: "simple suffix", podName: "log-agent-a1b2c", want: "log-agent"},
		{name: "unchanged", podName: "gateway", want: "gateway"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ExtractWorkloadName(test.podName); got != test.want {
				t.Fatalf("ExtractWorkloadName(%q) = %q, want %q", test.podName, got, test.want)
			}
		})
	}
}

func TestExtractWorkloadNameWithEvent(t *testing.T) {
	tests := []struct {
		name    string
		podName string
		event   mb.Event
		want    string
	}{
		{
			name:    "uses workload name from event",
			podName: "ignored-7d8f9c6b4f-abc12",
			event:   mb.Event{ModuleFields: mapstr.M{"deployment": mapstr.M{"name": "checkout"}}},
			want:    "checkout",
		},
		{
			name:    "uses precompiled pattern for detected kind",
			podName: "checkout-7d8f9c6b4f-abc12",
			event:   mb.Event{MetricSetFields: mapstr.M{"deployment": mapstr.M{}}},
			want:    "checkout",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ExtractWorkloadNameWithEvent(test.podName, test.event); got != test.want {
				t.Fatalf("ExtractWorkloadNameWithEvent(%q) = %q, want %q", test.podName, got, test.want)
			}
		})
	}
}
