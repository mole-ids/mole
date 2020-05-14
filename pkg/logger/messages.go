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
