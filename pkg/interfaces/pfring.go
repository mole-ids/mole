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

// +build pf_ring

package interfaces

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pfring"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/pkg/errors"
)

func init() {
	pfringAvaliable = true
}

// initPFRing initializes PFRing on the interface defined in the config
func (iface *Interfaces) initPFRing() (gopacket.PacketDataSource, error) {
	var ring *pfring.Ring
	var err error

	if iface.ifaceSet() {
		ring, err = pfring.NewRing(iface.Config.IFace, snapshotLength, pfring.FlagPromisc)
		if err != nil {
			return nil, errors.Wrap(err, PFRingInitFaildMsg)
		}
	} else {
		return nil, ErrPCAPPFRing
	}

	// If there is a BPF fitler then apply it
	if iface.Config.BPFfilter != "" {
		if err = ring.SetBPFFilter(iface.Config.BPFfilter); err != nil {
			return nil, errors.Wrap(err, SettingBPFFilterFailedMsg)
		}
	}

	err = ring.Enable()
	if err != nil { // Must do this!, or you don't get packets!
		return nil, errors.Wrap(err, EnablePFRingFailedMsg)
	}

	logger.Log.Info(PFRingEnabledMsg)
	return ring, nil
}
