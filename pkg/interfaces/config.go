package interfaces

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	IFace     string
	PFRing    bool
	BPFfilter string
}

// InitConfig initializes interface package
func InitConfig() (*Config, error) {
	config := &Config{
		IFace:     viper.GetString("interface.iface"),
		PFRing:    viper.GetBool("interface.pf_ring"),
		BPFfilter: viper.GetString("interface.bpf"),
	}
	if config.IFace == "" {
		return nil, fmt.Errorf("an interface name is needed")
	}

	ok, err := validateIface(config.IFace)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("the interface %s is not valid", config.IFace)
	}

	return config, nil
}
