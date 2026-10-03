//go:build with_ebpf && (linux || android)

package core

import (
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestSocketCreatorABI(t *testing.T) {
	if got := unsafe.Sizeof(SocketCreator{}); got != 64 {
		t.Fatalf("creator size=%d, want 64", got)
	}
	for name, offsets := range map[string][2]uintptr{
		"Cookie":          {unsafe.Offsetof(SocketCreator{}.Cookie), 0},
		"StartTimeNs":     {unsafe.Offsetof(SocketCreator{}.StartTimeNs), 8},
		"ProcessID":       {unsafe.Offsetof(SocketCreator{}.ProcessID), 16},
		"ThreadID":        {unsafe.Offsetof(SocketCreator{}.ThreadID), 20},
		"UserID":          {unsafe.Offsetof(SocketCreator{}.UserID), 24},
		"Flags":           {unsafe.Offsetof(SocketCreator{}.Flags), 28},
		"Comm":            {unsafe.Offsetof(SocketCreator{}.Comm), 32},
		"ProcessNameHash": {unsafe.Offsetof(SocketCreator{}.ProcessNameHash), 48},
		"ExeInode":        {unsafe.Offsetof(SocketCreator{}.ExeInode), 56},
	} {
		if offsets[0] != offsets[1] {
			t.Errorf("creator %s offset=%d, want %d", name, offsets[0], offsets[1])
		}
	}
}

func TestSocketCreatorValidity(t *testing.T) {
	valid := SocketCreator{Cookie: 42, StartTimeNs: 123, ProcessID: 10, ThreadID: 11, UserID: 0, Flags: SocketCreatorValid}
	for _, test := range []struct {
		name   string
		change func(*SocketCreator)
		valid  bool
	}{
		{"root UID", func(*SocketCreator) {}, true},
		{"other flags alongside valid", func(c *SocketCreator) { c.Flags |= 1 << 4 }, true},
		{"missing flag", func(c *SocketCreator) { c.Flags = 0 }, false},
		{"cookie zero", func(c *SocketCreator) { c.Cookie = 0 }, false},
		{"start zero", func(c *SocketCreator) { c.StartTimeNs = 0 }, false},
		{"pid zero", func(c *SocketCreator) { c.ProcessID = 0 }, false},
		{"tid zero", func(c *SocketCreator) { c.ThreadID = 0 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.change(&value)
			if got := value.IsValid(); got != test.valid {
				t.Fatalf("IsValid=%v, want %v", got, test.valid)
			}
			assignment := TCAssignment{SocketCookie: value.Cookie, Creator: value}
			if got := assignment.HasSocketCreator(); got != test.valid {
				t.Fatalf("HasSocketCreator=%v, want %v", got, test.valid)
			}
		})
	}
	if (TCAssignment{SocketCookie: valid.Cookie + 1, Creator: valid}).HasSocketCreator() {
		t.Fatal("creator from another cookie accepted")
	}
	if (TCAssignment{Creator: valid}).HasSocketCreator() {
		t.Fatal("zero assignment cookie accepted")
	}
}

func TestSocketCreatorMapLayoutValidation(t *testing.T) {
	valid := CiliumEBPF.MapInfo{Type: CiliumEBPF.SkStorage, KeySize: 4, ValueSize: 64, MaxEntries: 0, Flags: bpfFlagNoPrealloc}
	for _, test := range []struct {
		name   string
		change func(*CiliumEBPF.MapInfo)
		valid  bool
	}{
		{"valid", func(*CiliumEBPF.MapInfo) {}, true},
		{"wrong map type", func(i *CiliumEBPF.MapInfo) { i.Type = CiliumEBPF.Hash }, false},
		{"wrong key size", func(i *CiliumEBPF.MapInfo) { i.KeySize = 8 }, false},
		{"short value", func(i *CiliumEBPF.MapInfo) { i.ValueSize = 40 }, false},
		{"v1 value", func(i *CiliumEBPF.MapInfo) { i.ValueSize = 48 }, false},
		{"long value", func(i *CiliumEBPF.MapInfo) { i.ValueSize = 72 }, false},
		{"nonzero capacity", func(i *CiliumEBPF.MapInfo) { i.MaxEntries = 1 }, false},
		{"no NO_PREALLOC", func(i *CiliumEBPF.MapInfo) { i.Flags = 0 }, false},
		{"CLONE flag", func(i *CiliumEBPF.MapInfo) { i.Flags |= 512 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := valid
			test.change(&info)
			err := validateSocketCreatorMapInfo(&info)
			if (err == nil) != test.valid {
				t.Fatalf("validation=%v, want valid %v", err, test.valid)
			}
		})
	}
	if validateSocketCreatorMapInfo(nil) == nil {
		t.Fatal("nil map info accepted")
	}
}

func TestSocketCreatorOptionalFields(t *testing.T) {
	creator := SocketCreator{Flags: SocketCreatorValid}
	if creator.HasProcessName() || creator.HasExecutable() {
		t.Fatal("optional fields reported without their flags")
	}
	creator.Flags |= SocketCreatorNameValid
	if !creator.HasProcessName() || creator.HasExecutable() {
		t.Fatal("name flag not independent")
	}
	creator.Flags = SocketCreatorValid | SocketCreatorExeValid
	if creator.HasProcessName() || !creator.HasExecutable() {
		t.Fatal("exe flag not independent")
	}
	creator.Flags = SocketCreatorValid | SocketCreatorNameValid | SocketCreatorNameTruncated | 77<<8
	if creator.NameLength() != 77 || !creator.HasProcessName() {
		t.Fatalf("name length %d", creator.NameLength())
	}
}

func TestCookieTagMapLayoutValidation(t *testing.T) {
	// netd's cookie_tag_map: HASH, u64 cookie -> UidTagValue{u32 uid; u32 tag}.
	valid := CiliumEBPF.MapInfo{Type: CiliumEBPF.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 10000}
	for _, test := range []struct {
		name   string
		change func(*CiliumEBPF.MapInfo)
		valid  bool
	}{
		{"valid", func(*CiliumEBPF.MapInfo) {}, true},
		{"any capacity", func(i *CiliumEBPF.MapInfo) { i.MaxEntries = 1 }, true},
		{"wrong map type", func(i *CiliumEBPF.MapInfo) { i.Type = CiliumEBPF.LRUHash }, false},
		{"wrong key size", func(i *CiliumEBPF.MapInfo) { i.KeySize = 4 }, false},
		{"wrong value size", func(i *CiliumEBPF.MapInfo) { i.ValueSize = 4 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := valid
			test.change(&info)
			err := validateCookieTagMapInfo(&info)
			if (err == nil) != test.valid {
				t.Fatalf("validation=%v, want valid %v", err, test.valid)
			}
		})
	}
	if validateCookieTagMapInfo(nil) == nil {
		t.Fatal("nil map info accepted")
	}
}

func TestTCAssignmentCharge(t *testing.T) {
	if (TCAssignment{ChargeUID: 10123, IdentityFlags: TCIdentityChargeChecked}).HasCharge() {
		t.Fatal("charge reported without the valid flag")
	}
	if !(TCAssignment{IdentityFlags: TCIdentityChargeChecked | TCIdentityChargeValid}).HasCharge() {
		t.Fatal("valid charge not reported")
	}
}
