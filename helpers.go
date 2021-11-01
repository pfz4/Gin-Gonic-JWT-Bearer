package jwtbearer

import (
	"regexp"
	"strings"
)

func sliceContainsValue(slice []string, value string) bool{
	for _, sliceValue := range slice{
		if sliceValue==value{
			return true
		}
	}
	return false
}
func matchWildcardSlice(slice []string, value string) bool{
	for _, sliceValue := range slice{
		if ok,_:=regexp.MatchString(wildCardToRegexp(sliceValue), value);ok{
			return true
		}
	}
	return false
}

func wildCardToRegexp(pattern string) string {
    var result strings.Builder
    for i, literal := range strings.Split(pattern, "*") {

        // Replace * with .*
        if i > 0 {
            result.WriteString(".*")
        }

        // Quote any regular expression meta characters in the
        // literal text.
        result.WriteString(regexp.QuoteMeta(literal))
    }
    return result.String()
}