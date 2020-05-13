package engine

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"github.com/pkg/errors"

	"github.com/jpalanco/mole/internal/merr"
	"github.com/jpalanco/mole/internal/tree"
	"github.com/jpalanco/mole/internal/types"
	"github.com/jpalanco/mole/pkg/interfaces"
	"github.com/jpalanco/mole/pkg/logger"
	"github.com/jpalanco/mole/pkg/rules"
)

// Engine is in charge to handle the mole core functionalities
type Engine struct {
	// Config engine's configuration most of its values come from the arguments
	// or configuration file
	Config *Config
	// RulesManager handles everything related with rules
	RulesManager *rules.Manager
	// RuleMap used to fire Yara rules based on the identifier token return by
	// the look up query
	RuleMap types.RuleMapScanner
	// ring used for sniff packages from pf_ring
	ring *pfring.Ring
}

var (
	// netProtos network protocols allowed in mole
	netProtos = []gopacket.LayerType{layers.LayerTypeIPv4}

	// transProtos transport protocols allowed in mole
	transProtos = []gopacket.LayerType{layers.LayerTypeTCP,
		layers.LayerTypeUDP}
)

// New builds a new Engine
func New() (motor *Engine, err error) {
	// Create a new object and initialize it based on its configuration
	motor = &Engine{}
	motor.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, "unable to initiate engine config")
	}

	// Get the rules manager
	motor.RulesManager, err = rules.NewManager()
	if err != nil {
		return nil, errors.Wrap(err, "unable to initiate rules manager")
	}

	// Build a Decision tree and the RuleMap
	motor.RuleMap, err = tree.FromRules(motor.RulesManager.RawRules)
	if err != nil {
		return nil, errors.Wrap(err, "while generating the Decision tree")
	}

	// Initialize interfaces
	iface, err := interfaces.New()
	if err != nil {
		logger.Log.Fatalf(logger.UnableInitInterfaceMsg, err.Error())
	}

	// Enable pf_ring if requested
	if iface.PFRingEnabled() {
		motor.ring, err = iface.InitPFRing()
		if err != nil {
			logger.Log.Fatalf(merr.PFRingConfigErr, err.Error())
		}
	}

	logger.Log.Info(logger.MoleInitiatedMsg)

	return motor, err
}

// FireRules finds the set of rules that will be used to analyze the network packet
func (motor *Engine) FireRules(meta types.MetaRule, data gopacket.Payload) {
	// Look for a matching rule set based on paket metadata
	id, err := tree.LookupID(meta)
	if err != nil {
		logger.Log.Infof(merr.YaraRuleNotFoundMsg, meta)
		return
	}

	// If there is a match, then execute the Yara rules associated
	if scanner, found := motor.RuleMap[id]; found {

		matches, err := scanner.ScanMem(data.Payload())
		if err != nil {
			logger.Log.Errorf(logger.YaraScannerFaildMsg, err.Error())
			return
		}

		// matches are the results from the scan
		for _, match := range matches {
			// This is where mole is logging the resutls
			// TODO: This is a PoC at the moment, this needs a complete
			// rewrite
			var meta, strs string
			for k, vi := range match.Meta {
				v := vi.(string)
				if meta == "" {
					meta = fmt.Sprintf("%s:%s", k, v)
				} else {
					meta = fmt.Sprintf("%s|%s:%s", meta, k, v)
				}
			}

			for idx, sm := range match.Strings {
				if idx == 0 {
					strs = fmt.Sprintf("%s:%d:%x", sm.Name, sm.Offset, sm.Data)
				} else {
					strs = fmt.Sprintf("%s|%s:%d:%x", strs, sm.Name, sm.Offset, sm.Data)
				}
			}

			logger.Result.Infow("match",
				"rule", match.Rule,
				"namespace", match.Namespace,
				"tags", strings.Join(match.Tags, ","),
				"meta", meta,
				"strings", strs,
			)
		}
	}
}

// Start read packages and fire Yara rules agains those packets
func (motor *Engine) Start() {
	logger.Log.Info("engine is listening for packages")

	var err error
	var payload gopacket.Payload
	var meta types.MetaRule
	meta = make(types.MetaRule)

	// Start sniffing packages
	// TODO: Take into account when pf_ring is not enable or another method is
	// in used
	packetSource := gopacket.NewPacketSource(motor.ring, layers.LinkTypeEthernet)
	for pkt := range packetSource.Packets() {
		// Checking for network errors
		if err := pkt.ErrorLayer(); err != nil {
			logger.Log.Errorf(logger.ErrorProcessingLayerMsg, pkt.ErrorLayer().LayerType)
			continue
		}

		// Extract data from network layer.
		// First check whether the packet belongs to the layer
		// Second validate if the layer type or protocol is one of
		// the mole allowed protocols
		netLink := pkt.NetworkLayer()
		if netLink != nil && inProtos(netLink.LayerType(), netProtos) {
			payload, err = extractMetaFrom("network", pkt, meta)
			if err != nil {
				logger.Log.Error(err.Error())
			}
		}

		// Extract data from transport layer
		// First check whether the packet belongs to the layer
		// Second validate if the layer type or protocol is one of
		// the mole allowed protocols
		transportLink := pkt.TransportLayer()
		if transportLink != nil && inProtos(transportLink.LayerType(), transProtos) {
			payload, err = extractMetaFrom("transport", pkt, meta)
			if err != nil {
				logger.Log.Error(err.Error())
			}
		}

		// if there is an error, just continue
		if err != nil {
			continue
		}

		// Once metadata was extracted a decision neets to be taken
		logger.Log.Infof(logger.MetadataExtractedMsg, meta)
		motor.FireRules(meta, payload)
	}
}

// transProtos extract metadata from the packet
func extractMetaFrom(typ string, pkt gopacket.Packet, meta types.MetaRule) (payload gopacket.Payload, err error) {
	switch typ {
	// case "network":
	// 	netLink := pkt.NetworkLayer()
	// 	meta["proto"], err = types.NewMRProto(netLink.LayerType().String())
	// 	if err != nil {
	// 		return payload, errors.Wrap(err, "extracting 'proto' from LayerType IP")
	// 	}
	// 	return payload, errors.New("WIP")
	// var ip4 layers.IPv4
	// parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ip4)
	// decoded := []gopacket.LayerType{}
	// if err := parser.DecodeLayers(pkt.Data(), &decoded); err != nil {
	// 	return errors.New("unable to decode packet")
	// }

	// for _, layerType := range decoded {
	// 	switch layerType {
	// 	case layers.LayerTypeIPv4:
	// 		fmt.Println(" IP4 ", ip4.SrcIP, ip4.DstIP)
	// 	}
	// }

	case "transport":
		var err error

		var eth layers.Ethernet
		var ip4 layers.IPv4
		var tcp layers.TCP
		var udp layers.UDP
		var payload gopacket.Payload

		// Decode package
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp, &payload)
		decodedLayers := make([]gopacket.LayerType, 0, 10)
		err = parser.DecodeLayers(pkt.Data(), &decodedLayers)

		// Porcess each layer and get the metadata from each one
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeEthernet:
				continue
			case layers.LayerTypeIPv4:
				meta["src"], err = types.NewSRCMRAddress(ip4.SrcIP.String())
				if err != nil {
					return payload, errors.Wrap(err, "extracting 'src' from LayerType IP")
				}
				meta["dst"], err = types.NewDSTMRAddress(ip4.DstIP.String())
				if err != nil {
					return payload, errors.Wrap(err, "extracting 'dst' from LayerType IP")
				}
			case layers.LayerTypeTCP:
				meta["proto"], err = types.NewMRProto(tcp.LayerType().String())
				if err != nil {
					return payload, errors.Wrap(err, "extracting 'proto' from LayerType TCP")
				}
				meta["src_port"], err = types.NewSRCMRPort(fmt.Sprintf("%d", tcp.SrcPort))
				if err != nil {
					return payload, errors.Wrap(err, "extracting 'src_port' from LayerType TCP")
				}
				meta["dst_port"], err = types.NewDSTMRPort(fmt.Sprintf("%d", tcp.DstPort))
				if err != nil {
					return payload, errors.Wrap(err, "extracting 'dst_port' from LayerType TCP")
				}
			case layers.LayerTypeUDP:
				meta["proto"], err = types.NewMRProto(udp.LayerType().String())
				if err != nil {
					return payload, errors.Wrap(err, "extracting 'proto' from LayerType UDP")
				}
				meta["src_port"], err = types.NewSRCMRPort(fmt.Sprintf("%d", udp.SrcPort))
				if err != nil {
					return payload, errors.Wrap(err, "extracting 'src_port' from LayerType UDP")
				}
				meta["dst_port"], err = types.NewDSTMRPort(fmt.Sprintf("%d", udp.DstPort))
				if err != nil {
					return payload, errors.Wrap(err, "extracting 'dst_port' from LayerType UDP")
				}
			case gopacket.LayerTypePayload:
				continue
			}
		}
		// TODO: handle fragmented packages
		// if decodedLayers.Truncated {
		// 	fmt.Println("  Packet has been truncated")
		// }
		if err != nil {
			return payload, errors.Wrap(err, merr.WhileDecodingPaketMsg)
		}

		return payload, nil
	}

	return payload, errors.Errorf(merr.UnkownPaketTypeMsg, typ)
}
