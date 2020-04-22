package rules

import (
	"io/ioutil"
	"regexp"
)

// RemoveCStyleComments removes C-Style comments from a byte arry
func RemoveCStyleComments(content []byte) []byte {
	// http://blog.ostermiller.org/find-comment
	ccmt := regexp.MustCompile(`/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/`)
	return ccmt.ReplaceAll(content, []byte(""))
}

// RemoveCppStyleComments removes C++-Style comments from a byte arry
func RemoveCppStyleComments(content []byte) []byte {
	cppcmt := regexp.MustCompile(`//.*`)
	return cppcmt.ReplaceAll(content, []byte(""))
}

// RemoveCAndCppComments removes either C-Style or C++Style comments from
// a file
func RemoveCAndCppComments(srcpath string) []byte {
	b, err := ioutil.ReadFile(srcpath)
	if err != nil {
		panic(err)
	}
	return RemoveCppStyleComments(RemoveCStyleComments(b))
}
