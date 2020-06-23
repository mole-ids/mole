// Copyright 2020 Jaume Martin

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package engine

import (
	"net"
	"strconv"
	"strings"

	"github.com/mole-ids/mole/internal/types"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/pkg/errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketExtractor struct {
	Packet   gopacket.Packet
	Metadata *gopacket.PacketMetadata

	NetworkLayer     string
	TransportLayer   string
	ApplicationLayer string

	Network     gopacket.Layer
	Transport   gopacket.Layer
	Application gopacket.Layer

	// Network layers
	ipv4 *layers.IPv4

	// Transport layers
	tcp  *layers.TCP
	udp  *layers.UDP
	sctp *layers.SCTP

	// Application layers
}

func NewPacketExtractor(pkt gopacket.Packet) *PacketExtractor {
	return &PacketExtractor{
		Packet:   pkt,
		Metadata: pkt.Metadata(),
	}
}

func (pe *PacketExtractor) AddNetworkLayer(typ string, layer gopacket.Layer) error {
	typ = strings.ToLower(typ)
	if inProtos(typ, moleNetworkProtos) {
		var ok bool

		switch typ {
		case "ipv4":
			pe.Network = layer
			pe.NetworkLayer = typ
			pe.ipv4, ok = layer.(*layers.IPv4)

			if !ok {
				return errors.Errorf("Layer is not %s compatible", typ)
			}
		default:
			return errors.New("Proto not recognized by Mole")
		}
	} else {
		return errors.New("Proto not recognized by Mole")
	}

	return nil
}

func (pe *PacketExtractor) AddTransportLayer(typ string, layer gopacket.Layer) error {
	typ = strings.ToLower(typ)
	if inProtos(strings.ToLower(typ), moleTransportProtos) {
		var ok bool

		pe.Transport = layer
		pe.TransportLayer = typ
		switch typ {
		case "tcp":
			pe.tcp, ok = layer.(*layers.TCP)

			if !ok {
				return errors.Errorf("Layer is not %s compatible", typ)
			}
		case "udp":
			pe.udp, ok = layer.(*layers.UDP)

			if !ok {
				return errors.Errorf("Layer is not %s compatible", typ)
			}
		case "sctp":
			pe.sctp, ok = layer.(*layers.SCTP)

			if !ok {
				return errors.Errorf("Layer is not %s compatible", typ)
			}
		default:
			return errors.New("Proto not recognized by Mole")
		}

	} else {
		return errors.New("Proto not recognized by Mole")
	}

	return nil
}

func (pe *PacketExtractor) AddApplicationLayer(typ string, layer gopacket.Layer) error {
	return nil
}

func (pe *PacketExtractor) GetPacketPayload() []byte {
	return pe.Packet.Data()
}

func (pe *PacketExtractor) GetPacketMetadata() *gopacket.PacketMetadata {
	return pe.Packet.Metadata()
}

func (pe *PacketExtractor) GetIPv4() *layers.IPv4 {
	return pe.ipv4
}

func (pe *PacketExtractor) GetTCP() *layers.TCP {
	return pe.tcp
}

func (pe *PacketExtractor) GetUDP() *layers.UDP {
	return pe.udp
}

func (pe *PacketExtractor) GetSCTP() *layers.SCTP {
	return pe.sctp
}

func (pe *PacketExtractor) GetIfaceName() string {
	iface, err := net.InterfaceByIndex(pe.Metadata.InterfaceIndex)
	if err != nil {
		return ""
	}
	return iface.Name
}

func (pe *PacketExtractor) GetMetadata() (meta types.MetaRule) {
	var err error
	meta = make(types.MetaRule)

	switch pe.NetworkLayer {
	case "ipv4":
		meta["src"], err = types.NodeSrcAddress(pe.ipv4.SrcIP.String())
		if err != nil {
			logger.Log.Errorf("while building a IPv4 SRC Node for: %s:any --> %s:any", pe.ipv4.SrcIP.String(), pe.ipv4.DstIP.String())
		}
		meta["dst"], err = types.NodeDstAddress(pe.ipv4.DstIP.String())
		if err != nil {
			logger.Log.Errorf("while building a IPv4 DST Node for: %s:any --> %s:any", pe.ipv4.SrcIP.String(), pe.ipv4.DstIP.String())
		}
	}

	meta["proto"], _ = types.NodeProto(pe.TransportLayer)

	switch pe.TransportLayer {
	case "tcp":
		meta["sport"], err = types.NodeSrcMRPort(strconv.Itoa(int(pe.tcp.SrcPort)))
		if err != nil {
			logger.Log.Errorf("while building a TCP SPORT Node for: %s:%s --> %s:any", meta["src"].GetValue(), pe.tcp.SrcPort.String(), meta["dst"].GetValue())
		}
		meta["dport"], err = types.NodeDstMRPort(strconv.Itoa(int(pe.tcp.DstPort)))
		if err != nil {
			logger.Log.Errorf("while building a TCP DPORT Node for: %s:%s --> %s:%s", meta["src"].GetValue(), meta["sport"].GetValue(), meta["dst"].GetValue(), pe.tcp.DstPort.String())
		}
	case "udp":
		meta["sport"], err = types.NodeSrcMRPort(strconv.Itoa(int(pe.udp.SrcPort)))
		if err != nil {
			logger.Log.Errorf("while building a UDP SPORT Node for: %s:%s --> %s:any", meta["src"].GetValue(), pe.udp.SrcPort.String(), meta["dst"].GetValue())
		}
		meta["dport"], err = types.NodeDstMRPort(strconv.Itoa(int(pe.udp.DstPort)))
		if err != nil {
			logger.Log.Errorf("while building a UDP DPORT Node for: %s:%s --> %s:%s", meta["src"].GetValue(), meta["sport"].GetValue(), meta["dst"].GetValue(), pe.udp.DstPort.String())
		}
	case "stcp":
		meta["sport"], err = types.NodeSrcMRPort(strconv.Itoa(int(pe.sctp.SrcPort)))
		if err != nil {
			logger.Log.Errorf("while building a SCTP SPORT Node for: %s:%s --> %s:any", meta["src"].GetValue(), pe.sctp.SrcPort.String(), meta["dst"].GetValue())
		}
		meta["dport"], err = types.NodeDstMRPort(strconv.Itoa(int(pe.sctp.DstPort)))
		if err != nil {
			logger.Log.Errorf("while building a SCTP DPORT Node for: %s:%s --> %s:%s", meta["src"].GetValue(), meta["sport"].GetValue(), meta["dst"].GetValue(), pe.sctp.DstPort.String())
		}
	}
	return meta
}
