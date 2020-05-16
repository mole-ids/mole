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
	"net"

	"github.com/mole-ids/mole/internal/merr"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/pkg/errors"
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
		return nil, errors.Wrap(err, merr.InterfaceInitFailedMsg)
	}

	logger.Log.Info(logger.InterfacesInitiatedMsg)
	return iface, nil
}

// PFRingEnabled indicated whether PF Ring is enabled
func (iface *Interfaces) PFRingEnabled() bool {
	return iface.Config.PFRing
}

// validateIface validates the interface against the interfaces from the system
func validateIface(interfaceName string) (ok bool, err error) {
	ok = false
	inets, err := net.Interfaces()
	if err != nil {
		return ok, errors.Wrap(err, merr.InterfacesListFailesMsg)
	}

	for _, inet := range inets {
		if inet.Name == interfaceName {
			ok = true
			break
		}
	}
	return ok, nil
}
