package rules

var (
	// Keywords defines what Yara metadata entries are used for processing the rule.
	// This array also defines the order in which each key is taking into account
	Keywords = []string{"proto", "src", "src_port", "dst", "dst_port"}
)
