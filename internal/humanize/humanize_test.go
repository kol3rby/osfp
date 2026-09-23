package humanize

import (
	"testing"
	"time"
)

func TestCount(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0"},
		{7, "7"},
		{999, "999"},
		{1000, "1,000"},
		{12345, "12,345"},
		{498233, "498,233"},
		{1000000, "1,000,000"},
		{-1234, "-1,234"},
	}
	for _, tt := range tests {
		if got := Count(tt.in); got != tt.want {
			t.Errorf("Count(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestBytes(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{3174, "3.1 KiB"},
		{88 << 20, "88.0 MiB"},
		{3*1024*1024*1024 + 512*1024*1024, "3.5 GiB"},
		{5 << 40, "5.0 TiB"},
	}
	for _, tt := range tests {
		if got := Bytes(tt.in); got != tt.want {
			t.Errorf("Bytes(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		// A scan of a small tree must not be reported as having taken no time.
		{300 * time.Microsecond, "300µs"},
		{12 * time.Millisecond, "12ms"},
		{2*time.Minute + 14*time.Second, "2m14s"},
		{4*time.Second + 512*time.Millisecond, "4.5s"},
	}
	for _, tt := range tests {
		if got := Duration(tt.in); got != tt.want {
			t.Errorf("Duration(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMode(t *testing.T) {
	tests := []struct {
		in   uint32
		want string
	}{
		{0o644, "0644"},
		{0o755, "0755"},
		{0o4755, "04755"},
		{0, "00"},
	}
	for _, tt := range tests {
		if got := Mode(tt.in); got != tt.want {
			t.Errorf("Mode(%#o) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPlural(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "filesystems"},
		{1, "filesystem"},
		{2, "filesystems"},
		{-1, "filesystem"},
	}
	for _, tt := range tests {
		if got := Plural(tt.n, "filesystem", "filesystems"); got != tt.want {
			t.Errorf("Plural(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
