package utils

// InStrings search a string in a list of strings
func InStrings(key string, values []string) bool {
	for _, v := range values {
		if key == v {
			return true
		}
	}
	return false
}

// InInts search a int in a list of ints
func InInts(i int, lport []int) bool {
	for _, p := range lport {
		if p == i {
			return true
		}
	}
	return false
}
