package interfaces

import (
	"net"

	"github.com/jpalanco/mole/pkg/logger"
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
		return nil, errors.Wrap(err, "unable to initiate interfaces configutation")
	}

	logger.Log.Info("interfaces initiated successfully")
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
		return ok, errors.Wrap(err, "unable to list system interfaces")
	}

	for _, inet := range inets {
		if inet.Name == interfaceName {
			ok = true
			break
		}
	}
	return ok, nil
}
