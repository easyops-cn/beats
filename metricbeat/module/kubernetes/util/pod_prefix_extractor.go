package util

import (
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func DuplicateWorkloadInfo(fields mapstr.M, workloadNameKey string, event mb.Event) {
	workloadNameValue, _ := fields.GetValue(workloadNameKey)

	workloadName, _ := workloadNameValue.(string)

	event.ModuleFields.DeepUpdate(mapstr.M{
		"workload": mapstr.M{
			"name": workloadName,
		},
	})
}
