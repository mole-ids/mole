package engine

import "github.com/google/gopacket"

func inProtos(pkgProto gopacket.LayerType, protos []gopacket.LayerType) bool {
	for _, proto := range protos {
		if proto == pkgProto {
			return true
		}
	}
	return false
}
