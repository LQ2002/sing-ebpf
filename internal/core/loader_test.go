//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"slices"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestRawCgroupAttachPrefersMulti(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	callCount := 0
	var options link.RawAttachProgramOptions
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		callCount++
		options = current
		return nil
	}
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Fatalf("raw attach called %d times, want one multi-program attempt", callCount)
	}
	if options.Target != 42 || options.Attach != CiliumEBPF.AttachCgroupInetSockRelease || options.Flags != unix.BPF_F_ALLOW_MULTI {
		t.Fatalf("raw attach options = %+v, want target=42 attach=socket_release flags=BPF_F_ALLOW_MULTI", options)
	}
}

func TestRawCgroupAttachMultiOnlyNeverFallsBack(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	callCount := 0
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		callCount++
		if current.Flags != unix.BPF_F_ALLOW_MULTI {
			t.Fatalf("multi-only probe used flags %#x", current.Flags)
		}
		return unix.EPERM
	}
	if err := attachProgramRawMultiOnly(42, nil, CiliumEBPF.AttachCgroupInetSockRelease); !errors.Is(err, unix.EPERM) {
		t.Fatalf("multi-only attach error = %v, want EPERM", err)
	}
	if callCount != 1 {
		t.Fatalf("multi-only attach called %d times, want one attempt", callCount)
	}
}

func TestRawCgroupAttachFallsBackToExclusiveAfterMultiCompatibilityError(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	var flags []uint32
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		if current.Target != 42 || current.Attach != CiliumEBPF.AttachCGroupInet4Connect {
			t.Fatalf("unexpected attach options: %+v", current)
		}
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EPERM
		}
		return nil
	}
	if err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI, 0}) {
		t.Fatalf("flags=%v, want [ALLOW_MULTI, 0]", flags)
	}
}

func TestRawCgroupAttachPreservesExistingOwner(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	originalQuery := queryCgroupPrograms
	t.Cleanup(func() {
		rawAttachProgram = originalRawAttachProgram
		queryCgroupPrograms = originalQuery
	})
	var flags []uint32
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EPERM
		}
		return nil
	}
	queryCgroupPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
		return &link.QueryResult{Programs: []link.AttachedProgram{{ID: 1}}}, nil
	}
	if err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect); err == nil {
		t.Fatal("existing cgroup owner was replaced")
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only the non-destructive multi attach", flags)
	}
}

func TestRawCgroupAttachFallbackErrors(t *testing.T) {
	for _, multiErr := range []error{
		unix.EINVAL,
		unix.EPERM,
		unix.ENOTSUP,
		unix.EOPNOTSUPP,
		linuxErrnoNotSupported,
	} {
		t.Run(multiErr.Error(), func(t *testing.T) {
			originalRawAttachProgram := rawAttachProgram
			t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
			var flags []uint32
			rawAttachProgram = func(current link.RawAttachProgramOptions) error {
				flags = append(flags, current.Flags)
				if current.Flags == unix.BPF_F_ALLOW_MULTI {
					return multiErr
				}
				return nil
			}
			if err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI, 0}) {
				t.Fatalf("flags=%v, want [ALLOW_MULTI, 0]", flags)
			}
		})
	}
}

func TestRawCgroupAttachDoesNotFallbackOnFatalError(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	wantErr := unix.EACCES
	callCount := 0
	rawAttachProgram = func(link.RawAttachProgramOptions) error {
		callCount++
		return wantErr
	}
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if callCount != 1 {
		t.Fatalf("raw attach called %d times, want no exclusive fallback", callCount)
	}
}

type objectMapLayout struct {
	keySize   uint32
	valueSize uint32
}

func TestTCLocalProgramsDoNotUseTGIDHelper(t *testing.T) {
	spec, err := loadTC()
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{
		"classifier/local_egress_ethernet_mark",
		"classifier/local_egress_raw_ip_mark",
		"classifier/local_egress_ethernet_process",
		"classifier/local_egress_raw_ip_process",
		"classifier/local_egress_ethernet_creator",
		"classifier/local_egress_raw_ip_creator",
	} {
		for _, program := range spec.Programs {
			if program.SectionName != section {
				continue
			}
			for _, instruction := range program.Instructions {
				if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnGetCurrentPidTgid {
					t.Fatalf("section %q still uses the TGID helper", section)
				}
			}
		}
	}
}

func programCallsHelper(program *CiliumEBPF.ProgramSpec, helper asm.BuiltinFunc) bool {
	for _, instruction := range program.Instructions {
		if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == helper {
			return true
		}
	}
	return false
}

// TestTCLocalProgramsReadSelfBypassStorage pins down which helper each local
// egress program reaches for, because the two are no longer the same question.
// Recognising sing-box's own sockets is socket local storage and every variant
// must do it, or the proxy's own traffic gets intercepted and loops. Reading the
// socket cookie is now only about recording the owner into tc_assignment, which
// is what the process-tracking variants exist for, so the plain marking variants
// must not pay for it.
func TestTCLocalProgramsReadSelfBypassStorage(t *testing.T) {
	spec, err := loadTC()
	if err != nil {
		t.Fatal(err)
	}
	// section -> whether it should also read the socket cookie
	sections := map[string]bool{
		"classifier/local_egress_ethernet_mark":    false,
		"classifier/local_egress_raw_ip_mark":      false,
		"classifier/local_egress_ethernet_process": true,
		"classifier/local_egress_raw_ip_process":   true,
		"classifier/local_egress_ethernet_creator": true,
		"classifier/local_egress_raw_ip_creator":   true,
	}
	for _, program := range spec.Programs {
		wantCookie, selected := sections[program.SectionName]
		if !selected {
			continue
		}
		if !programCallsHelper(program, asm.FnSkStorageGet) {
			t.Errorf("section %q does not read self-bypass socket storage", program.SectionName)
		}
		if gotCookie := programCallsHelper(program, asm.FnGetSocketCookie); gotCookie != wantCookie {
			t.Errorf("section %q socket-cookie helper=%v, want %v", program.SectionName, gotCookie, wantCookie)
		}
		delete(sections, program.SectionName)
	}
	if len(sections) != 0 {
		t.Fatalf("missing TC sections: %v", sections)
	}
}

// TestTCLocalProgramsCacheTheirVerdict guards the wiring of the per-socket
// verdict cache. Losing it would not fail anything: the classifier would simply
// go back to running the whole policy chain -- including the LPM trie walk that
// is the most expensive lookup in it -- on every packet of every flow, and the
// only symptom would be CPU nobody is measuring.
func TestTCLocalProgramsCacheTheirVerdict(t *testing.T) {
	spec, err := loadTC()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Maps["tc_local_verdict"] == nil {
		t.Fatal("TC object is missing the verdict cache map")
	}
	sections := []string{
		"classifier/local_egress_ethernet_mark",
		"classifier/local_egress_raw_ip_mark",
		"classifier/local_egress_ethernet_process",
		"classifier/local_egress_raw_ip_process",
		"classifier/local_egress_ethernet_creator",
		"classifier/local_egress_raw_ip_creator",
	}
	for _, section := range sections {
		var program *CiliumEBPF.ProgramSpec
		for _, candidate := range spec.Programs {
			if candidate.SectionName == section {
				program = candidate
				break
			}
		}
		if program == nil {
			t.Errorf("missing TC section %q", section)
			continue
		}
		found := false
		for _, instruction := range program.Instructions {
			if instruction.Reference() == "tc_local_verdict" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("section %q does not reference the verdict cache", section)
		}
	}
}

func TestCgroupReleaseNotificationUsesRingBufferHelper(t *testing.T) {
	spec, err := loadCgroup()
	if err != nil {
		t.Fatal(err)
	}
	foundSection := false
	for _, program := range spec.Programs {
		if program.SectionName != "cgroup/sock_release_notify" {
			continue
		}
		foundSection = true
		foundHelper := false
		for _, instruction := range program.Instructions {
			if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnRingbufOutput {
				foundHelper = true
				break
			}
		}
		if !foundHelper {
			t.Fatal("cgroup socket-release notification does not use ring-buffer output")
		}
	}
	if !foundSection {
		t.Fatal("missing cgroup socket-release notification section")
	}
	watch := spec.Maps["cgroup_udp_release_watch"]
	if watch == nil || watch.KeySize != 8 || watch.ValueSize != 1 {
		t.Fatalf("invalid cgroup UDP release watch map: %+v", watch)
	}
	events := spec.Maps["cgroup_udp_release_events"]
	if events == nil || events.Type != CiliumEBPF.RingBuf {
		t.Fatalf("invalid cgroup UDP release event map: %+v", events)
	}
	stats := spec.Maps["cgroup_udp_release_stats"]
	if stats == nil || stats.Type != CiliumEBPF.PerCPUArray || stats.KeySize != 4 || stats.ValueSize != 8 {
		t.Fatalf("invalid cgroup UDP release stats map: %+v", stats)
	}
}

func TestEmbeddedTCObjectLayout(t *testing.T) {
	testEmbeddedObjectLayout(t, loadTC, map[string]objectMapLayout{
		"tc_control":          {4, 76},
		"tc_listener_sockets": {4, 4},
		"tc_assignment":       {44, 112},
		"socket_creators":     {4, 64},
		"netd_cookie_tags":    {8, 8},
		"tc_stats":            {4, 8},
		// Socket local storage carries no key of its own: the socket is the
		// key, so the kernel reports a key size of zero.
		"tc_self_sockets":        {0, 4},
		"tc_local_verdict":       {0, 8},
		"tc_uid_policy":          {8, 1},
		"tc_local_bypass_ipv4":   {8, 1},
		"tc_local_bypass_ipv6":   {20, 1},
		"tc_shared_bypass_ipv4":  {8, 1},
		"tc_shared_bypass_ipv6":  {20, 1},
		"tc_include_source_ipv4": {8, 1},
		"tc_include_source_ipv6": {20, 1},
		"tc_exclude_source_ipv4": {8, 1},
		"tc_exclude_source_ipv6": {20, 1},
		"tc_include_source_mac":  {8, 1},
		"tc_exclude_source_mac":  {8, 1},
		"tc_host_ipv4":           {4, 1},
		"tc_host_ipv6":           {16, 1},
		"tc_local_bypass_port":   {4, 1},
		"tc_shared_bypass_port":  {4, 1},
	}, []string{
		"classifier/local_egress_ethernet_mark",
		"classifier/local_egress_raw_ip_mark",
		"classifier/local_egress_ethernet_process",
		"classifier/local_egress_raw_ip_process",
		"classifier/local_egress_ethernet_creator",
		"classifier/local_egress_raw_ip_creator",
		"classifier/shared_ingress_ethernet",
		"classifier/shared_ingress_raw_ip",
		"classifier/delivery_ingress",
	})
}

func testEmbeddedObjectLayout(
	t *testing.T,
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]objectMapLayout,
	sections []string,
) {
	t.Helper()
	spec, err := loadSpec()
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range maps {
		actual := spec.Maps[name]
		if actual == nil {
			t.Errorf("missing map %q", name)
			continue
		}
		if actual.KeySize != expected.keySize || actual.ValueSize != expected.valueSize {
			t.Errorf(
				"map %q has key/value size %d/%d, want %d/%d",
				name,
				actual.KeySize,
				actual.ValueSize,
				expected.keySize,
				expected.valueSize,
			)
		}
	}
	availableSections := make(map[string]bool, len(spec.Programs))
	for _, program := range spec.Programs {
		availableSections[program.SectionName] = true
	}
	for _, section := range sections {
		if !availableSections[section] {
			t.Errorf("missing program section %q", section)
		}
	}
}

func TestKernelProgramNames(t *testing.T) {
	// Keep this list aligned with program_name.go. Besides enforcing the kernel
	// limit, global uniqueness prevents diagnostics from making two concurrently
	// loaded roles look like the same program.
	names := []string{
		kernelProgramNameCgroupConnect4,
		kernelProgramNameCgroupSendmsg4,
		kernelProgramNameCgroupRecvmsg4,
		kernelProgramNameCgroupConnect6,
		kernelProgramNameCgroupSendmsg6,
		kernelProgramNameCgroupRecvmsg6,
		kernelProgramNameCgroupRelease,
		kernelProgramNameTCLocalEthernet,
		kernelProgramNameTCLocalRawIP,
		kernelProgramNameTCSharedEthernet,
		kernelProgramNameTCSharedRawIP,
		kernelProgramNameTCDelivery,
		kernelProgramNameSharedIngress,
		kernelProgramNameSharedEgress,
		kernelProgramNameICMPLocalEthernet,
		kernelProgramNameICMPLocalRawIP,
		kernelProgramNameICMPSharedEthernet,
		kernelProgramNameICMPSharedRawIP,
		kernelProgramNameSelfCreate,
		kernelProgramNameSelfRelease,
		kernelProgramNameSelfConnect4,
		kernelProgramNameSelfConnect6,
		kernelProgramNameSelfSendmsg4,
		kernelProgramNameSelfSendmsg6,
		kernelProgramNameProcessConnect4,
		kernelProgramNameProcessConnect6,
		kernelProgramNameProcessSendmsg4,
		kernelProgramNameProcessSendmsg6,
		kernelProgramNameProcessRelease,
		kernelProgramNameReleaseProbe,
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if len(name) == 0 || len(name) > 15 {
			t.Fatalf("invalid kernel program name %q: length %d", name, len(name))
		}
		if _, exists := seen[name]; exists {
			t.Fatalf("duplicate kernel program name: %s", name)
		}
		seen[name] = struct{}{}
	}
}

// Legacy mark/process variants must not reference creator storage. Referenced
// map symbols survive bpf2go relocation and expose accidental shared call paths.
func TestTCSocketCreatorVariantIsolation(t *testing.T) {
	spec, err := loadTC()
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]bool{
		"classifier/local_egress_ethernet_mark":    false,
		"classifier/local_egress_raw_ip_mark":      false,
		"classifier/local_egress_ethernet_process": false,
		"classifier/local_egress_raw_ip_process":   false,
		"classifier/local_egress_ethernet_creator": true,
		"classifier/local_egress_raw_ip_creator":   true,
	}
	for _, program := range spec.Programs {
		want, selected := sections[program.SectionName]
		if !selected {
			continue
		}
		found, foundCharge := false, false
		for _, ins := range program.Instructions {
			switch ins.Reference() {
			case "socket_creators":
				found = true
			case "netd_cookie_tags":
				foundCharge = true
			}
		}
		if found != want {
			t.Errorf("section %s creator reference=%v, want %v", program.SectionName, found, want)
		}
		// The netd placeholder is only created for creator variants, so no
		// other section may reference it.
		if foundCharge != want {
			t.Errorf("section %s cookie tag reference=%v, want %v", program.SectionName, foundCharge, want)
		}
		if want && (!programCallsHelper(program, asm.FnGetSocketCookie) || !programCallsHelper(program, asm.FnSkStorageGet)) {
			t.Errorf("creator section %s lacks required socket helpers", program.SectionName)
		}
		delete(sections, program.SectionName)
	}
	if len(sections) != 0 {
		t.Fatalf("missing sections: %v", sections)
	}
	info := spec.Maps["socket_creators"]
	if info == nil || info.Type != CiliumEBPF.SkStorage || info.KeySize != 4 || info.ValueSize != 64 || info.MaxEntries != 0 || info.Flags != bpfFlagNoPrealloc {
		t.Fatalf("bad creator map ABI: %+v", info)
	}
}

// The BPF compiler can lower even a constant-size C builtin to an external
// libcall. CollectionSpec parsing succeeds, but loading such a program fails
// before the verifier runs. Every symbolic BPF-to-BPF call must resolve within
// the program after cilium links the object's subprograms.
func TestEmbeddedTCProgramsHaveNoUnresolvedCalls(t *testing.T) {
	spec, err := loadTC()
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range spec.Programs {
		symbols, err := program.Instructions.SymbolOffsets()
		if err != nil {
			t.Fatalf("section %s symbols: %v", program.SectionName, err)
		}
		for index, instruction := range program.Instructions {
			// -1 is the unresolved offset used by cilium. Numeric calls whose
			// offsets are already encoded need no symbolic reference.
			if !instruction.IsFunctionReference() || instruction.Constant != -1 {
				continue
			}
			reference := instruction.Reference()
			if _, found := symbols[reference]; reference == "" || !found {
				t.Errorf("section %s instruction %d has unresolved function reference %q", program.SectionName, index, reference)
			}
		}
	}
}
