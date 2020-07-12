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
package utils

import (
	"net"
)

// InStrings search a string in a list of strings
func InStrings(key string, values []string) bool {
	for _, v := range values {
		if key == v {
			return true
		}
	}
	return false
}

// InInts search a int in a list of ints
func InInts(i int, lport []int) bool {
	for _, p := range lport {
		if p == i {
			return true
		}
	}
	return false
}

// InNets search a int in a list of nets
func InNets(i *net.IPNet, lport []*net.IPNet) bool {
	for _, p := range lport {
		if p.Contains(i.IP) {
			return true
		}
	}
	return false
}
