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
	LoggerInitSuccessMsg      = "logger successfully initiated in %s level"
	LoggerMoleInitSuccessMsg  = "mole logger successfully initiated"
	StartingMoleMsg           = "starting mole ids"
	ExtractMetaFromLayerMsg   = "protocol not allowed"
	ExtractTransporDataMsg    = "protocol not allowed in transport"
	MetadataExtractedMsg      = "extracted from network packet: %v"
	UnableInitInterfaceMsg    = "unable to initiate interfaces: %s"
	MoleInitiatedMsg          = "starting mole ids engine"
	EngineListeningMsg        = "mole ids engine is ready and listening for packages"
	ErrorProcessingLayerMsg   = "while reading package at layer %d"
	InterfacesInitiatedMsg    = "starting interfaces"
	PfRingInitiatedMsg        = "starting pf_ring "
	YaraRulesInitiatedMsg     = "yara rules loaded successfully"
	YaraRulesLoadedMsg        = "loaded %d rules without errors in %fs"
	RuleMapBuiltMsg           = "building rules map"
	YaraScannerFaildMsg       = "error while scanning payload: %s"
	IndexAndDirAreAbsoluteMsg = "assuming index file and rules directory to be absolute references"
	DirRelativeMsg            = "assumimng yara rules directory to be relative to %s"
	IndexRelativeMsg          = "assuming yara index file to be relative to %s"
	UsingIndexRuleFileMsg     = "using %s as index file"
	RulesIndexFileMsg         = "loading rules using index %s file"
	RulesFolderMsg            = "loading rules from directory %s"
)
