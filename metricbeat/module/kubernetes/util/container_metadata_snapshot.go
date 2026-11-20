package util

import "github.com/elastic/elastic-agent-libs/mapstr"

func containerMetadataSnapshot(pod mapstr.M) mapstr.M {
	container := make(mapstr.M, len(pod)+1)
	for key, value := range pod {
		container[key] = value
	}
	switch fields := pod["container"].(type) {
	case mapstr.M:
		container["container"] = fields.Clone()
	case map[string]interface{}:
		container["container"] = mapstr.M(fields).Clone()
	}
	return container
}
