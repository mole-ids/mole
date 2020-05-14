package merr

import "errors"

const (
	LoggerInitConfigMsg      = "getting logger config"
	LoggerBuildZapFieldsMsg  = "while compiling logger options"
	YaraScanMemMsg           = "error while scanning payload"
	YaraRuleNotFoundMsg      = "unable to find yara rule for %v"
	PFRingConfigErr          = "error while initiating pf_ring: %s"
	PFRingCreateObjectMsg    = "unable to crate new pf_ring onject"
	WhileDecodingPaketMsg    = "while decoding packet"
	UnkownPaketTypeMsg       = "type %s not recognized"
	InterfaceInitFailedMsg   = "unable to initiate interfaces configutation"
	InterfacesListFailesMsg  = "unable to list system interfaces"
	BPFFilterSetMsg          = "unable to define BPF filter"
	BPFFilterEnableMsg       = "unable to enable pf_ring"
	OpenRuleFilesMsg         = "could not open rule file %s"
	OpenRulesDirMsg          = "could not open rules directory"
	AbsIndexPathMsg          = "unable to get the absolute path for index file %s"
	YaraReadFileMsg          = "unable to read the yara rule %s"
	RuleOrIndexNotDefinedMsg = "either a rule index or rule folder have to be defined"
	InitRulesManagerMsg      = "unable to initiate rules manager config"
	LoadingRulesMsg          = "while loading rules"
	YaraRuleMetadataMsg      = "unable to get metadata from yrule %s"
	InsertYaraMsg            = "unable to insert rule %s"
	YaraCompilerMsg          = "unable to create yara compiler"
	NoPreviousYaraRulesMsg   = "unable to rules from previous rules"
	YaraNewScannerMsg        = "unable to get a new scanner"
	DecisionTreeNotInitMsg   = "decision tree not initialized"
	CreateTreeNodeAtLevelMsg = "when creating node at level %d with key %s"
	SolutionNotFoundMsg      = "solution not found"
)

var (
	LoggerInitConfigErr      = errors.New(LoggerInitConfigMsg)
	LoggerBuildZapFieldsErr  = errors.New(LoggerBuildZapFieldsMsg)
	YaraScanMemErr           = errors.New(YaraScanMemMsg)
	RuleOrIndexNotDefinedErr = errors.New(RuleOrIndexNotDefinedMsg)
	YaraCompilerErr          = errors.New(YaraCompilerMsg)
	NoPreviousYaraRulesErr   = errors.New(NoPreviousYaraRulesMsg)
	YaraNewScannerErr        = errors.New(YaraNewScannerMsg)
	DecisionTreeNotInitErr   = errors.New(DecisionTreeNotInitMsg)
	SolutionNotFoundErr      = errors.New(SolutionNotFoundMsg)
)
