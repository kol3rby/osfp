// Package cstr converts the fixed-size C character arrays that system calls
// return into Go strings.
//
// It exists because the element type of those arrays is not the same on every
// target — byte on most, int8 on some — while their meaning is identical. One
// generic function is better than one copy per operating system in every
// package that calls uname(2) or statfs(2).
package cstr

// String returns the NUL-terminated string held in a C character array.
func String[T ~byte | ~int8](chars []T) string {
	b := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
