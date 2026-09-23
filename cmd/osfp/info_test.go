package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInfo(t *testing.T) {
	_, fingerprint := baselineTree(t)

	out := captureStdout(t)
	if code := runCmd(t, "info", "-b", fingerprint); code != exitOK {
		t.Fatalf("info exited %d", code)
	}
	text := out.String()

	for _, want := range []string{
		"tool         osfp",
		"created      ",
		"key          ",
		"privileged   ",
		"scope        ",
		"entries      ",
		"size         ",
		"digest       ",
		"exclusions   ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("info output is missing %q:\n%s", want, text)
		}
	}
	// A fingerprint taken without privileges must say so where nobody can
	// miss it: it is the first thing that decides whether it is usable.
	if os.Geteuid() != 0 && !strings.Contains(text, "UNPRIVILEGED") {
		t.Errorf("an unprivileged fingerprint is not marked as such:\n%s", text)
	}
	if !strings.Contains(text, "/proc") {
		t.Errorf("the recorded exclusions are not listed:\n%s", text)
	}
}

func TestInfoJSON(t *testing.T) {
	_, fingerprint := baselineTree(t)

	out := captureStdout(t)
	if code := runCmd(t, "info", "-b", fingerprint, "--json"); code != exitOK {
		t.Fatalf("info --json exited %d", code)
	}

	var meta map[string]any
	if err := json.Unmarshal(out.Bytes(), &meta); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	for _, key := range []string{"tool", "created_at", "os_key", "system", "privileged", "scan", "exclusions"} {
		if _, ok := meta[key]; !ok {
			t.Errorf("the JSON metadata has no %q field: %v", key, meta)
		}
	}
}

func TestVerify(t *testing.T) {
	_, fingerprint := baselineTree(t)

	t.Run("a sound fingerprint", func(t *testing.T) {
		out := captureStdout(t)
		if code := runCmd(t, "verify", "-b", fingerprint); code != exitOK {
			t.Fatalf("verify exited %d", code)
		}
		if !strings.Contains(out.String(), ": OK") || !strings.Contains(out.String(), "sha256") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("quiet", func(t *testing.T) {
		out := captureStdout(t)
		if code := runCmd(t, "verify", "-b", fingerprint, "--quiet"); code != exitOK {
			t.Fatalf("verify --quiet exited %d", code)
		}
		if out.Len() != 0 {
			t.Errorf("--quiet printed %q", out)
		}
	})

	t.Run("a damaged fingerprint", func(t *testing.T) {
		body, err := os.ReadFile(fingerprint)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		damaged := filepath.Join(t.TempDir(), "damaged.osfp")
		body[len(body)/2] ^= 0x01
		if err := os.WriteFile(damaged, body, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		captureStdout(t)
		if code := runCmd(t, "verify", "-b", damaged); code != exitError {
			t.Fatalf("verify exited %d on a damaged file, want %d", code, exitError)
		}
	})
}

// TestInfoAndVerifyNeedNoPrivileges is the other half of §7.5: the commands
// that only read a fingerprint never ask for root, and never warn about it.
func TestInfoAndVerifyNeedNoPrivileges(t *testing.T) {
	_, fingerprint := baselineTree(t)
	for _, cmd := range []string{"info", "verify"} {
		t.Run(cmd, func(t *testing.T) {
			captureStdout(t)
			// No --allow-non-root anywhere: the command must simply work.
			if code := runCmd(t, cmd, "-b", fingerprint); code != exitOK {
				t.Fatalf("%s exited %d", cmd, code)
			}
		})
	}
}

func TestInfoAndVerifyRejectBadArguments(t *testing.T) {
	_, fingerprint := baselineTree(t)
	tests := [][]string{
		{"info"},
		{"verify"},
		{"info", "-b", "/nonexistent.osfp"},
		{"verify", "-b", "/nonexistent.osfp"},
		{"info", "-b", fingerprint, "stray"},
		{"verify", "-b", fingerprint, "stray"},
	}
	captureStdout(t)
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if code := runCmd(t, args...); code != exitError {
				t.Errorf("exited %d, want %d", code, exitError)
			}
		})
	}
}
