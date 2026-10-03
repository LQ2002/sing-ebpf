//go:build with_ebpf && (linux || android)

package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Executes the production C state transitions with mocked kernel helpers.
// Verifier acceptance and real socket packets belong to the integration tests.
func TestTCSocketCreatorNativeTransitions(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("host C compiler unavailable")
	}
	// A compiled test binary may run from a different working directory, or on
	// a target device without the host sources used to build this harness.
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("host test source location unavailable")
	}
	source := filepath.Join(filepath.Dir(testFile), "testdata", "tc_socket_creator_test.c")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("host C test source unavailable: %v", err)
	}
	binary := filepath.Join(t.TempDir(), "tc-creator-test")
	output, err := exec.Command(compiler, "-O2", "-Wno-attributes", "-o", binary, source).CombinedOutput()
	if err != nil {
		t.Fatalf("compile native helper test: %v\n%s", err, output)
	}
	output, err = exec.Command(binary).CombinedOutput()
	if err != nil {
		t.Fatalf("native helper transitions: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}
