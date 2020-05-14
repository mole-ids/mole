package types

var (
	// Keywords defines what Yara metadata entries are used for processing the rule.
	// This array also defines the order in which each key is taking into account
	Keywords = []string{"proto", "src", "src_port", "dst", "dst_port"}

	// RuleDefVersion defines the version of the metadata accepted by Mole
	// this will be handy to version rules later on
	RuleDefVersion = "1.0"

	// RangeSplitter character used to define a range, like ports 80:443
	RangeSplitter = ":"
	// SequenceSplitter character used to define a sequence, like ports 80,443
	SequenceSplitter = ","
)
