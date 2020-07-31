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

import (
	"github.com/hillu/go-yara/v4"
	"github.com/mole-ids/mole/pkg/logger/models"
)

// inProtos checks `pkgProto` exists in  `protos`
func inProtos(proto string, protos []string) bool {
	for _, p := range protos {
		if p == proto {
			return true
		}
	}
	return false
}

func extractMeta(metas []yara.Meta, key string) interface{} {
	for _, meta := range metas {
		if meta.Identifier == key {
			return meta.Value
		}
	}
	return nil
}

func toMoleMetaMap(metas []yara.Meta) models.MetaMap {
	var obj models.MetaMap
	obj = make(models.MetaMap)

	for _, meta := range metas {
		obj[meta.Identifier] = meta.Value
	}
	return obj
}
