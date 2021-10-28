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
func wildcardSliceContainsValue(slice []string, value string) bool{
	for _, sliceValue := range slice{
		if ok,_:=regexp.MatchString("^"+strings.Replace(regexp.QuoteMeta(sliceValue), "\\*", ".*", -1)+"$", value);ok{
			return true
		}
	}
	return false
}