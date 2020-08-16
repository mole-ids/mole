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
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/pkg/errors"
)

const (
	snapshotLength = 65536
)

var (
	pfringAvaliable = false
)

// Interfaces is in charge to manage interfaces
type Interfaces struct {
	// Config interface's configuration most of its values come from the arguments
	// or configuration file
	Config *Config
}

// New builds and configure the interface object
func New() (iface *Interfaces, err error) {
	iface = &Interfaces{}
	iface.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, InterfaceConfigInitFailedMsg)
	}

	logger.Log.Info(InterfacesInitMsg)
	return iface, nil
}

// PFRingAvaliable indicated whether PF Ring is enabled
func (iface *Interfaces) PFRingAvaliable() bool {
	return pfringAvaliable
}

// PFRingEnabled indicated whether PF Ring is enabled
func (iface *Interfaces) PFRingEnabled() bool {
	return iface.Config.PFRing
}

// GetHandler returns the data source where the packets will came in from
func (iface *Interfaces) GetHandler() (handle gopacket.PacketDataSource, err error) {
	// Enable pf_ring if requested
	if pfringAvaliable {
		if iface.Config.PFRing {
			handle, err = iface.initPFRing()
			if err != nil {
				return nil, errors.Wrap(err, PFRingInitFailMsg)
			}
		} else {
			handle, err = iface.initPcap()
			if err != nil {
				return nil, errors.Wrap(err, PCAPInitFailMsg)
			}
		}
	} else {
		if iface.Config.PFRing {
			logger.Log.Warn(PFRingNotAvaliableMsg)
		}
		handle, err = iface.initPcap()
		if err != nil {
			return nil, errors.Wrap(err, PCAPInitFailMsg)
		}
	}

	return handle, nil
}

func (iface *Interfaces) ifaceSet() bool {
	return iface.Config.IFace != ""
}

func (iface *Interfaces) pcapFileSet() bool {
	return iface.Config.File != ""
}

func (iface *Interfaces) TrafficHandler() string {
	if iface.ifaceSet() {
		return iface.Config.IFace
	}

	return iface.Config.File
}

// validateIface validates the interface against the interfaces from the system
func validateIface(interfaceName string) (ok bool, err error) {
	ok = false
	inets, err := pcap.FindAllDevs()
	if err != nil {
		return ok, errors.Wrap(err, InterfacesListFailedMsg)
	}

	for _, inet := range inets {
		if inet.Name == interfaceName {
			ok = true
			break
		}
	}
	return ok, nil
}

func validateFilename(filename string) (ok bool, err error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false, ErrPcapFileNoExist
	}
	return ok, nil
}
