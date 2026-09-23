package cstr

import "testing"

func TestString(t *testing.T) {
	t.Run("byte array", func(t *testing.T) {
		var a [8]byte
		copy(a[:], "ext4")
		if got := String(a[:]); got != "ext4" {
			t.Errorf("String = %q, want ext4", got)
		}
	})

	t.Run("int8 array, as Solaris and older Darwin spell it", func(t *testing.T) {
		var a [8]int8
		for i, c := range []byte("zfs") {
			a[i] = int8(c)
		}
		if got := String(a[:]); got != "zfs" {
			t.Errorf("String = %q, want zfs", got)
		}
	})

	t.Run("no terminator", func(t *testing.T) {
		a := [4]byte{'a', 'b', 'c', 'd'}
		if got := String(a[:]); got != "abcd" {
			t.Errorf("String = %q, want abcd", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		var a [4]byte
		if got := String(a[:]); got != "" {
			t.Errorf("String = %q, want the empty string", got)
		}
		if got := String([]byte(nil)); got != "" {
			t.Errorf("String(nil) = %q", got)
		}
	})
}
