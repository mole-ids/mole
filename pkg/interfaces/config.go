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
	"fmt"

	"github.com/spf13/viper"
)

// Config interface internal configuration
type Config struct {
	// IFace interface to bind to
	IFace string
	// PFRing enable pf_ring
	PFRing bool
	// BPFfilter BPF filter
	BPFfilter string
}

// InitConfig initializes interface package
func InitConfig() (*Config, error) {
	config := &Config{
		IFace:     viper.GetString("interface.iface"),
		PFRing:    viper.GetBool("interface.pf_ring"),
		BPFfilter: viper.GetString("interface.bpf"),
	}

	// Check the minimal options
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
