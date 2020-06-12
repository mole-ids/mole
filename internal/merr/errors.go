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
package merr

import "errors"

const (
	LoggerInitConfigMsg             = "getting logger config"
	LoggerBuildZapFieldsMsg         = "while compiling logger options"
	YaraScanMemMsg                  = "error while scanning payload"
	YaraRuleNotFoundMsg             = "unable to find yara rule for proto:%s src:%s sport:%s dst:%s dport:%s"
	PFRingConfigErr                 = "error while initiating pf_ring: %s"
	PFRingCreateObjectMsg           = "unable to crate new pf_ring onject"
	WhileDecodingPaketMsg           = "while decoding packet"
	UnkownPaketTypeMsg              = "type %s not recognized"
	InterfaceInitFailedMsg          = "unable to initiate interfaces configutation"
	InterfacesListFailesMsg         = "unable to list system interfaces"
	BPFFilterSetMsg                 = "unable to define BPF filter"
	BPFFilterEnableMsg              = "unable to enable pf_ring"
	OpenRuleFilesMsg                = "could not open rule file %s"
	OpenRulesDirMsg                 = "could not open rules directory"
	AbsIndexPathMsg                 = "unable to get the absolute path for index file %s"
	YaraReadFileMsg                 = "unable to read the yara rule %s"
	RuleOrIndexNotDefinedMsg        = "either a rule index or rule folder have to be defined"
	InitRulesManagerMsg             = "unable to initiate rules manager config"
	LoadingRulesMsg                 = "while loading rules"
	YaraRuleMetadataMsg             = "while getting metadata info from %s"
	InsertYaraMsg                   = "unable to insert rule %s"
	YaraCompilerMsg                 = "unable to create yara compiler"
	NoPreviousYaraRulesMsg          = "unable to rules from previous rules"
	YaraNewScannerMsg               = "unable to get a new scanner"
	DecisionTreeNotInitMsg          = "decision tree not initialized"
	CreateTreeNodeAtLevelMsg        = "when creating node at level %d with key %s"
	SolutionNotFoundMsg             = "solution not found"
	WhileReadingFileMsg             = "while reading file"
	NodeTypeNotValidMsg             = "Node type %s not recognized"
	WhileBuildingRuleMetadataMsg    = "while building rule metadata"
	WhileLoadingRulesMsg            = "while loading rules"
	UndefinedMsg                    = "undefined error"
	WhileGettingNodeByTypeMsg       = "while getting node by type"
	WhileParsingCIDRMsg             = "while parsing CIDR address"
	MixedFormatsNotAllowedMsg       = "mixed formats are not allowed"
	ConversionTypeMsg               = "type convertion is not allowed"
	RangeExceededMsg                = "port range can not contain more than one range splitter"
	InvalidPortNumberMsg            = "value %s is not valid port number"
	PortBaundsNotValidMsg           = "lower port cannot be higher or equal to the higher port in port range"
	RuleFolderIsNotAbsMsg           = "rules folder is not an absolute path"
	IndexFileIsNotAbsMsg            = "rules index file is not an absolute path"
	ErrIndexOrRuleFolderRequiredMsg = "either rules folder or index file is required"
	WrongOutputFormatMsg            = "mole output format not recognized"
	BadRuleMetadataMsg              = "because entry %s has no value"
	CompileYaraRuleErrorMsg         = "Mole couldn't compile a yara rule because"
	KeywordsNotMeetMsg              = "keywork %s not found while processing the rule"
)

var (
	ErrLoggerInitConfig      = errors.New(LoggerInitConfigMsg)
	ErrLoggerBuildZapFields  = errors.New(LoggerBuildZapFieldsMsg)
	ErrYaraScanMem           = errors.New(YaraScanMemMsg)
	ErrRuleOrIndexNotDefined = errors.New(RuleOrIndexNotDefinedMsg)
	ErrYaraCompiler          = errors.New(YaraCompilerMsg)
	ErrNoPreviousYaraRules   = errors.New(NoPreviousYaraRulesMsg)
	ErrYaraNewScanner        = errors.New(YaraNewScannerMsg)
	ErrDecisionTreeNotInit   = errors.New(DecisionTreeNotInitMsg)
	ErrSolutionNotFound      = errors.New(SolutionNotFoundMsg)
	ErrUndefined             = errors.New(UndefinedMsg)
	ErrMixedFormats          = errors.New(MixedFormatsNotAllowedMsg)
	ErrConversionType        = errors.New(ConversionTypeMsg)
	ErrRangeExceeded         = errors.New(RangeExceededMsg)
	ErrPortBoundsNotValid    = errors.New(PortBaundsNotValidMsg)
	ErrRuleFolderIsNotAbs    = errors.New(RuleFolderIsNotAbsMsg)
	ErrIndexFileIsNotAbs     = errors.New(IndexFileIsNotAbsMsg)
	ErrWrongOutputFormat     = errors.New(WrongOutputFormatMsg)
)
