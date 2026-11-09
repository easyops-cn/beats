package util

import (
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func DuplicateWorkloadInfo(fields mapstr.M, workloadNameKey string, event mb.Event) {
	workloadNameValue, _ := fields.GetValue(workloadNameKey)

	workloadName, _ := workloadNameValue.(string)

	workload := mapstr.M{}
	switch existing := event.ModuleFields["workload"].(type) {
	case mapstr.M:
		for field, value := range existing {
			workload[field] = value
		}
	case map[string]interface{}:
		for field, value := range existing {
			workload[field] = value
		}
	}
	workload["name"] = workloadName
	event.ModuleFields["workload"] = workload
}
