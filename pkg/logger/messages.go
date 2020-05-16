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
package logger

const (
	LoggerInitSuccessMsg    = "logger initiated successfully"
	ExtractMetaFromLayerMsg = "protocol not allowed"
	ExtractTransporDataMsg  = "protocol not allowed in transport"
	MetadataExtractedMsg    = "extracted from network packet: %v"
	UnableInitInterfaceMsg  = "unable to initiate interfaces: %s"
	MoleInitiatedMsg        = "mole engine initiated successfully"
	EngineListeningMsg      = "engine is listening for packages"
	ErrorProcessingLayerMsg = "while reading package at layer %d"
	InterfacesInitiatedMsg  = "interfaces initiated successfully"
	PfRingInitiatedMsg      = "pf_ring initiated successfully"
	YaraRulesInitiatedMsg   = "yara rules loaded successfully"
	YaraRulesLoadedMsg      = "loaded %d rules"
	RuleMapBuiltMsg         = "rule map build successfully"
	YaraScannerFaildMsg     = "error while scanning payload: %s"
)
