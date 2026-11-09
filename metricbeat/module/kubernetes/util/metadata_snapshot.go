package util

import "github.com/elastic/elastic-agent-libs/mapstr"

func snapshotEventMetadata(source mapstr.M) mapstr.M {
	snapshot := make(mapstr.M, len(source))
	for key, value := range source {
		switch key {
		case "kubernetes":
			var fields mapstr.M
			switch typed := value.(type) {
			case mapstr.M:
				fields = typed
			case map[string]interface{}:
				fields = mapstr.M(typed)
			default:
				snapshot[key] = value
				continue
			}
			module := make(mapstr.M, len(fields))
			for field, child := range fields {
				module[field] = child
			}
			snapshot[key] = module
		case "container", "service":
			snapshot[key] = cloneMetadataValue(value)
		default:
			snapshot[key] = value
		}
	}
	return snapshot
}

func cloneMetadataValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case mapstr.M:
		return typed.Clone()
	case map[string]interface{}:
		return mapstr.M(typed).Clone()
	}
	return mapstr.M{"value": value}.Clone()["value"]
}
