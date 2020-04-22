package engine

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"github.com/pkg/errors"

	"github.com/jpalanco/mole/internal/tree"
	"github.com/jpalanco/mole/internal/types"
	"github.com/jpalanco/mole/pkg/interfaces"
	"github.com/jpalanco/mole/pkg/logger"
	"github.com/jpalanco/mole/pkg/rules"
)

// Engine is in charge to handle the mole core functionalities
type Engine struct {
	Config       *Config
	RulesManager *rules.Manager
	RuleMap      types.RuleMapScanner
	ring         *pfring.Ring
}

var (
	netProtos = []gopacket.LayerType{layers.LayerTypeIPv4}

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
	logger.Log.Info("rule manager initiated successfully")

	// Load rules from rules manager
	err = motor.RulesManager.LoadRules()
	if err != nil {
		return nil, errors.Wrap(err, "while loading rules")
	}
	logger.Log.Info("yara rules loaded successfully")

	// Build a decicion tree and the RuleMap
	motor.RuleMap, err = tree.FromRules(motor.RulesManager.RawRules)
	if err != nil {
		return nil, errors.Wrap(err, "while generating the decicion tree")
	}
	logger.Log.Info("rule map build successfully")

	iface, err := interfaces.New()
	if err != nil {
		logger.Log.Fatalf("unable to initiate interfaces: %s", err.Error())
	}
	logger.Log.Info("interfaces initiated successfully")

	if iface.PFRingEnabled() {
		motor.ring, err = iface.InitPFRing()
		if err != nil {
			logger.Log.Fatalf("unable to configure PF Ring: %s", err.Error())
		}
		logger.Log.Info("pf_ring initiated successfully")
	}

	return motor, err
}

// FireRules finds the set of rules that will be used to analyze the network packet
func (motor *Engine) FireRules(meta types.MetaRule, data gopacket.Payload) {
	id, err := tree.LookupID(meta)
	if err != nil {
		logger.Log.Infof("unable to find yara rule for %v", meta)
		logger.Log.Debugf("unable to find yara rule for %v", meta)
		return
	}

	if scanner, found := motor.RuleMap[id]; found {
		matches, err := scanner.ScanMem(data.Payload())
		if err != nil {
			logger.Log.Errorf("error while scanning payload: %s", err.Error())
			return
		}

		for _, match := range matches {
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

	packetSource := gopacket.NewPacketSource(motor.ring, layers.LinkTypeEthernet)
	for pkt := range packetSource.Packets() {
		if err := pkt.ErrorLayer(); err != nil {
			logger.Log.Errorf("while reading package at layer %d", pkt.ErrorLayer().LayerType)
			continue
		}
		netLink := pkt.NetworkLayer()
		if netLink != nil && inProtos(netLink.LayerType(), netProtos) {
			payload, err = extractMetaFrom("network", pkt, meta)
			if err != nil {
				logger.Log.Error(err.Error())
			}
		}

		transportLink := pkt.TransportLayer()
		if transportLink != nil && inProtos(transportLink.LayerType(), transProtos) {
			payload, err = extractMetaFrom("transport", pkt, meta)
			if err != nil {
				logger.Log.Error(err.Error())
			}
		}

		if err != nil {
			continue
		}

		logger.Log.Infof("extracted from network packet: %v", meta)
		motor.FireRules(meta, payload)
	}
}

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
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp, &payload)
		decodedLayers := make([]gopacket.LayerType, 0, 10)

		err = parser.DecodeLayers(pkt.Data(), &decodedLayers)
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
		// if decodedLayers.Truncated {
		// 	fmt.Println("  Packet has been truncated")
		// }
		if err != nil {
			return payload, errors.Wrap(err, "while decoding packet")
		}

		return payload, nil
	}
	return payload, errors.Errorf("type %s not recognized", typ)
}
