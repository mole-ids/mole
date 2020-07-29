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

const (
	MainEventOuterMsg         = "mole"
	MainEventInnerMsg         = "mole_event"
	MainEventInitCompletedMsg = "starting mole ids engine"
	StartMsg                  = "engine is listening for packages"
	NoMatchFoundMsg           = "unable to find yara rule for proto:%s src:%s sport:%s dst:%s dport:%s"
	ScannerScanMemFaildMsg    = "error while scanning payload: %s"
	UnableToDecodePacketMsg   = "unable to fully decode packet. Error in layer: %d"
	ConfigInitFailedMsg       = "while configuring the engine"
	RulesManagerInitFailMsg   = "while initialating rules manager got"
	CreateTreeFailMsg         = "while generating the Decision tree got"
	InterfacesInitFailMsg     = "while initialating interfaces got"
	LoadingRulesFailedMsg     = "while loading rules got"
	GettingHandlerFailMsg     = "while getting the snffer handler got"
)

var ()
