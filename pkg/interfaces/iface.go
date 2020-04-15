package interfaces

import (
	"net"

	"github.com/pkg/errors"
)

type Interfaces struct {
	Config *Config
}

func New() (iface *Interfaces, err error) {
	iface = &Interfaces{}
	iface.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, "unable to initiate interfaces configutation")
	}

	return iface, nil
}

func (iface *Interfaces) EnablePFRing() bool {
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
