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

package interfaces

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/pkg/errors"
)

// initPcap initializes PFRing on the interface defined in the config
func (iface *Interfaces) initPcap() (gopacket.PacketDataSource, error) {
	var handle *pcap.Handle
	var err error

	if iface.ifaceSet() {
		handle, err = pcap.OpenLive(iface.Config.IFace, snapshotLength, true, pcap.BlockForever)
		if err != nil {
			return nil, errors.Wrap(err, LiveSnifferFaildMsg)
		}
	} else {
		handle, err = pcap.OpenOffline(iface.Config.File)
		if err != nil {
			return nil, errors.Wrap(err, OfflineSnifferFaildMsg)
		}
	}

	// If there is a BPF fitler then apply it
	if iface.Config.BPFfilter != "" {
		if err = handle.SetBPFFilter(iface.Config.BPFfilter); err != nil {
			return nil, errors.Wrap(err, SettingBPFFilterFailedMsg)
		}
	}

	logger.Log.Info(PCAPEnabledMsg)
	return handle, nil
}
