package translate

import (
	"fmt"
	"strings"
)

// FlowLogsMap is what flow logs need on the target.
type FlowLogsMap struct {
	// Destination is where AWS delivers flow log records: an S3 bucket's
	// ARN, with a folder if wanted (arn:aws:s3:::shop-flow-logs/vpc/).
	// Azure writes flow logs to a container of its own in a storage
	// account, which no bucket stands for, so the bucket is a choice. AWS
	// only: GCP's go to Cloud Logging.
	Destination string `json:"destination,omitempty"`
	// Everywhere turns flow logs on for every translated network, where
	// the source logged only some or none. Left out, a network is logged
	// only where the source's was: logging is billed.
	Everywhere bool `json:"everywhere,omitempty"`
}

func (m Map) validateNSG() error {
	n := m.Network
	if n == nil {
		return nil
	}
	for _, k := range sortedMapKeys(n.NSGs) {
		if strings.Count(k, "/") != 1 || strings.Count(n.NSGs[k], "/") != 1 {
			return fmt.Errorf("map: network.nsgs: %q: %q is not group/nsg: group/network", k, n.NSGs[k])
		}
	}
	if f := n.FlowLogs; f != nil {
		switch {
		case m.To != "aws" && f.Destination != "":
			return fmt.Errorf("map: network.flowLogs.destination is for aws: GCP's flow logs go to Cloud Logging")
		case f.Destination != "" && !flowLogARN.MatchString(f.Destination):
			return fmt.Errorf("map: network.flowLogs.destination: %q is not an S3 bucket's ARN (arn:aws:s3:::bucket/folder/)", f.Destination)
		case f.Destination != "" && strings.Contains(f.Destination+"/", "/AWSLogs/"):
			return fmt.Errorf("map: network.flowLogs.destination: AWS keeps the folder AWSLogs for itself")
		}
	}
	return nil
}

// nsgNetwork is the network (group/network) the map writes an NSG in that
// nothing uses, or "".
func (m Map) nsgNetwork(key string) string {
	if m.Network == nil {
		return ""
	}
	for k, v := range m.Network.NSGs {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
