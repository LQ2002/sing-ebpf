//go:build with_ebpf && (linux || android)

package core

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Executes the production C state transitions with mocked kernel helpers.
// Verifier acceptance and real socket packets belong to the integration tests.
func TestTCSocketCreatorNativeTransitions(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("host C compiler unavailable")
	}
	binary := filepath.Join(t.TempDir(), "tc-creator-test")
	output, err := exec.Command(compiler, "-O2", "-Wno-attributes", "-o", binary, "testdata/tc_socket_creator_test.c").CombinedOutput()
	if err != nil {
		t.Fatalf("compile native helper test: %v\n%s", err, output)
	}
	output, err = exec.Command(binary).CombinedOutput()
	if err != nil {
		t.Fatalf("native helper transitions: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}
