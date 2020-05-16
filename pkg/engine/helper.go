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

import "github.com/google/gopacket"

// inProtos checks `pkgProto` exists in  `protos`
func inProtos(pkgProto gopacket.LayerType, protos []gopacket.LayerType) bool {
	for _, proto := range protos {
		if proto == pkgProto {
			return true
		}
	}
	return false
}
