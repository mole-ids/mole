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
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"github.com/pkg/errors"

	"github.com/mole-ids/mole/internal/merr"
	"github.com/mole-ids/mole/internal/tree"
	"github.com/mole-ids/mole/internal/types"
	"github.com/mole-ids/mole/pkg/interfaces"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/mole-ids/mole/pkg/rules"
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
	// moleProtos network protocols allowed in mole
	moleProtos = []gopacket.LayerType{layers.LayerTypeIPv4, layers.LayerTypeTCP,
		layers.LayerTypeUDP, layers.LayerTypeSCTP}
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
	motor.RuleMap, err = tree.FromRules(motor.RulesManager.GetRawRules())
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

// Start read packages and fire Yara rules against those packets
func (motor *Engine) Start() {
	logger.Log.Info("engine is listening for packages")

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

		go motor.disectProtos(pkt)
	}
}

func (motor *Engine) disectProtos(pkt gopacket.Packet) {
	var meta types.MetaRule
	var err error

	networkLayer := pkt.NetworkLayer()
	ipv4, ok := networkLayer.(*layers.IPv4)
	if ok {
		meta = make(types.MetaRule)
		meta["proto"], _ = types.NewMRProto("ip")
		meta["src"], err = types.NewSRCMRAddress(ipv4.SrcIP.String())
		if err != nil {
			logger.Log.Errorf("while building a IPv4 SRC Node for: %s:any --> %s:any", ipv4.SrcIP.String(), ipv4.DstIP.String())
		}
		meta["sport"], _ = types.NewSRCMRPort("0")
		meta["dst"], err = types.NewDSTMRAddress(ipv4.DstIP.String())
		if err != nil {
			logger.Log.Errorf("while building a IPv4 DST Node for: %s:any --> %s:any", ipv4.SrcIP.String(), ipv4.DstIP.String())
		}
		meta["dport"], _ = types.NewDSTMRPort("0")

		go motor.analyzeAndAlert(meta, pkt, networkLayer.LayerContents())
		switch ipv4.NextLayerType() {
		case layers.LayerTypeTCP:
			transportLayer := pkt.Layer(layers.LayerTypeTCP)
			tcp := transportLayer.(*layers.TCP)

			meta["proto"], _ = types.NewMRProto("tcp")
			meta["sport"], err = types.NewSRCMRPort(fmt.Sprintf("%d", tcp.SrcPort))
			if err != nil {
				logger.Log.Errorf("while building a TCP SPORT Node for: %s:%s --> %s:any", ipv4.SrcIP.String(), tcp.SrcPort, ipv4.DstIP.String())
			}
			meta["dport"], err = types.NewDSTMRPort(fmt.Sprintf("%d", tcp.DstPort))
			if err != nil {
				logger.Log.Errorf("while building a TCP DPORT Node for: %s:%s --> %s:%s", ipv4.SrcIP.String(), tcp.SrcPort, ipv4.DstIP.String(), tcp.DstPort)
			}
			go motor.analyzeAndAlert(meta, pkt, networkLayer.LayerContents())
		case layers.LayerTypeUDP:
			transportLayer := pkt.Layer(layers.LayerTypeUDP)
			udp := transportLayer.(*layers.UDP)

			meta["proto"], _ = types.NewMRProto("udp")
			meta["sport"], err = types.NewSRCMRPort(fmt.Sprintf("%d", udp.SrcPort))
			if err != nil {
				logger.Log.Errorf("while building a TCP SPORT Node for: %s:%s --> %s:any", ipv4.SrcIP.String(), udp.SrcPort, ipv4.DstIP.String())
			}
			meta["dport"], err = types.NewDSTMRPort(fmt.Sprintf("%d", udp.DstPort))
			if err != nil {
				logger.Log.Errorf("while building a TCP DPORT Node for: %s:%s --> %s:%s", ipv4.SrcIP.String(), udp.SrcPort, ipv4.DstIP.String(), udp.DstPort)
			}
			go motor.analyzeAndAlert(meta, pkt, networkLayer.LayerContents())
		case layers.LayerTypeSCTP:
			transportLayer := pkt.Layer(layers.LayerTypeSCTP)
			sctp := transportLayer.(*layers.SCTP)
			meta["proto"], _ = types.NewMRProto("sctp")
			meta["sport"], err = types.NewSRCMRPort(fmt.Sprintf("%d", sctp.SrcPort))
			if err != nil {
				logger.Log.Errorf("while building a TCP SPORT Node for: %s:%s --> %s:any", ipv4.SrcIP.String(), sctp.SrcPort, ipv4.DstIP.String())
			}
			meta["dport"], err = types.NewDSTMRPort(fmt.Sprintf("%d", sctp.DstPort))
			if err != nil {
				logger.Log.Errorf("while building a TCP DPORT Node for: %s:%s --> %s:%s", ipv4.SrcIP.String(), sctp.SrcPort, ipv4.DstIP.String(), sctp.DstPort)
			}
			go motor.analyzeAndAlert(meta, pkt, networkLayer.LayerContents())
		}
	}
}

func (motor *Engine) analyzeAndAlert(meta types.MetaRule, pkt gopacket.Packet, payload []byte) {
	// Look for a matching rule set based on paket metadata
	id, err := tree.LookupID(meta)
	if err != nil {
		logger.Log.Debugf(merr.YaraRuleNotFoundMsg, meta["proto"].GetValue(), meta["src"].GetValue(), meta["sport"].GetValue(), meta["dst"].GetValue(), meta["dport"].GetValue())
		return
	}

	// If there is a match, then execute the Yara rules associated
	if scanner, found := motor.RuleMap[id]; found {
		matches, err := scanner.ScanMem(pkt.Data())
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

			logger.Mole.Infow("match",
				"rule", match.Rule,
				"namespace", match.Namespace,
				"tags", strings.Join(match.Tags, ","),
				"meta", meta,
				"strings", strs,
			)
		}
	}
}
