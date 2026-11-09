package selector

import "testing"

// FuzzMatchGlob guards against panics in the hand-rolled glob matcher.
func FuzzMatchGlob(f *testing.F) {
	f.Add("myorg/api:*", "myorg/api:v1")
	f.Add("*", "anything")
	f.Add("a**b***c", "abxxxc")
	f.Add("", "x")
	f.Add("**", "")
	f.Fuzz(func(t *testing.T, pattern, str string) {
		_ = matchGlob(pattern, str)
	})
}
