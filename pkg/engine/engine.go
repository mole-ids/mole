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
	"runtime"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hillu/go-yara/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/mole-ids/mole/internal/nodes"
	"github.com/mole-ids/mole/internal/tree"
	"github.com/mole-ids/mole/internal/types"
	"github.com/mole-ids/mole/pkg/interfaces"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/mole-ids/mole/pkg/logger/models"
	"github.com/mole-ids/mole/pkg/rules"
)

// Engine is in charge to handle the mole core functionalities
type Engine struct {
	// Config engine's configuration most of its values come from the arguments
	// or configuration file
	Config *Config

	// Iface is the interface where Mole reads packets
	Iface *interfaces.Interfaces

	// RulesManager handles everything related with rules
	RulesManager *rules.Manager

	// RuleMap used to fire Yara rules based on the identifier token return by
	// the look up query
	RuleMap types.RuleMapScanner

	// Handle is the interface handeler that allow Mole to capture traffic
	Handle gopacket.PacketDataSource
}

var (
	// moleProtos network protocols allowed in mole
	moleNetworkProtos     = []string{"ipv4"}
	moleTransportProtos   = []string{"tcp", "udp", "sctp"}
	moleApplicationProtos = []string{}
)

const (
	IPV4 = "ipv4"

	TCP  = "tcp"
	UDP  = "udp"
	SCTP = "sctp"
)

// New builds a new Engine
func New() (motor *Engine, err error) {
	// Create a new object and initialize it based on its configuration
	motor = &Engine{}
	motor.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, ConfigInitFailedMsg)
	}

	// Get the rules manager
	motor.RulesManager, err = rules.NewManager()
	if err != nil {
		return nil, errors.Wrap(err, RulesManagerInitFailMsg)
	}

	// Load rules
	err = motor.RulesManager.LoadRules()
	if err != nil {
		return nil, errors.Wrap(err, LoadingRulesFailedMsg)
	}

	// Build a Decision tree and the RuleMap
	motor.RuleMap, err = tree.FromRules(motor.RulesManager.GetRawRules())
	if err != nil {
		return nil, errors.Wrap(err, CreateTreeFailMsg)
	}

	// Initialize interfaces
	motor.Iface, err = interfaces.New()
	if err != nil {
		return nil, errors.Wrap(err, InterfacesInitFailMsg)
	}

	motor.Handle, err = motor.Iface.GetHandler()
	if err != nil {
		return nil, errors.Wrap(err, GettingHandlerFailMsg)
	}

	logger.Log.Info(MainEventInitCompletedMsg)

	return motor, err
}

// Start read packages and fire Yara rules against those packets
func (motor *Engine) Start() {
	logger.Log.Info(StartMsg)

	// Start sniffing packages
	// TODO: Take into account when pf_ring is not enable or another method is
	// in used
	packetSource := gopacket.NewPacketSource(motor.Handle, layers.LinkTypeEthernet)
	for pkt := range packetSource.Packets() {
		// Checking for network errors
		if err := pkt.ErrorLayer(); err != nil {
			logger.Log.Errorf(UnableToDecodePacketMsg, pkt.ErrorLayer().LayerType)
			continue
		}

		go motor.extractLayers(pkt)
	}
}

func (motor *Engine) extractLayers(pkt gopacket.Packet) {
	var err error

	pe := NewPacketExtractor(pkt)

	network := pkt.NetworkLayer()
	if network != nil {
		if err = pe.AddNetworkLayer(network.LayerType().String(), network); err == nil {

			transport := pkt.TransportLayer()
			if transport != nil {
				if err = pe.AddTransportLayer(transport.LayerType().String(), transport); err == nil {

					application := pkt.ApplicationLayer()
					if application != nil {
						// TODO: handle application layer
						pe.AddApplicationLayer(application.LayerType().String(), application)

						motor.checkAndFire(pe)
					}
				}
			}
		}
	}
}

func (motor *Engine) checkAndFire(pe *PacketExtractor) {
	meta := pe.GetMetadata()

	matches, err := tree.LookupID(meta)
	if err != nil {
		logger.Log.Debugf(NoMatchFoundMsg,
			meta[nodes.Proto.String()].GetValue(),
			meta[nodes.SrcNet.String()].GetValue(),
			meta[nodes.SrcPort.String()].GetValue(),
			meta[nodes.DstNet.String()].GetValue(),
			meta[nodes.DstPort.String()].GetValue())
		return
	}

	logger.Log.Debugf("matching %d rules", len(matches))

	for _, matchID := range matches {
		if scanner, found := motor.RuleMap[matchID]; found {
			var matches yara.MatchRules
			scanner = scanner.SetCallback(&matches)

			err := scanner.ScanMem(pe.GetPacketPayload())
			if err != nil {
				logger.Log.Errorf(ScannerScanMemFaildMsg, err.Error())
				return
			}

			metadata := pe.GetPacketMetadata()
			for _, match := range matches {
				var event models.EveEvent

				event.Timestamp = &models.MoleTime{
					Time: metadata.Timestamp,
				}
				typ, ok := extractMeta(match.Metas, "type").(string)
				if !ok {
					event.EventType = "unkown"
				} else {
					event.EventType = typ
				}
				if runtime.GOOS == "windows" {
					event.InIface = motor.Iface.TrafficHandler()
				} else {
					event.InIface = pe.GetIfaceName()
				}
				event.Proto = meta[nodes.Proto.String()].GetValue()
				event.SrcIP = meta[nodes.SrcNet.String()].GetValue()
				event.DstIP = meta[nodes.DstNet.String()].GetValue()
				event.SrcPort, _ = strconv.Atoi(meta[nodes.SrcPort.String()].GetValue())
				event.DstPort, _ = strconv.Atoi(meta[nodes.DstPort.String()].GetValue())

				event.Alert = models.AlertEvent{
					Name: match.Rule,
					Tags: match.Tags,
					Meta: toMoleMetaMap(match.Metas),
				}

				var matchArr models.MatchArray
				for _, m := range match.Strings {
					matchArr = append(matchArr, models.MatchString{
						Name:   m.Name,
						Offset: m.Offset,
						Data:   m.Data,
					})
				}

				event.Matches = matchArr

				logger.Mole.Infow(MainEventOuterMsg, zap.Object(MainEventInnerMsg, &event))
			}
		}
	}
}

func (motor *Engine) ruleMatching(m []yara.MatchRule, err error) {

}
