package util

import (
	"fmt"
	"net"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
)

func metadataNodeNameForAddress(address string, watcher kubernetes.Watcher) (string, error) {
	if err := watcher.Start(); err != nil {
		return "", err
	}
	wanted := net.ParseIP(address)
	for _, object := range watcher.Store().List() {
		node, ok := object.(*kubernetes.Node)
		if !ok {
			continue
		}
		for _, candidate := range node.Status.Addresses {
			if wanted != nil && wanted.Equal(net.ParseIP(candidate.Address)) {
				return node.Name, nil
			}
		}
	}
	return "", fmt.Errorf("node address %s not found in node informer", address)
}
