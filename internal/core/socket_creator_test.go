//go:build with_ebpf && (linux || android)

package core

import (
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestSocketCreatorABI(t *testing.T) {
	if got := unsafe.Sizeof(SocketCreator{}); got != 48 {
		t.Fatalf("creator size=%d, want 48", got)
	}
	for name, offsets := range map[string][2]uintptr{
		"Cookie":      {unsafe.Offsetof(SocketCreator{}.Cookie), 0},
		"StartTimeNs": {unsafe.Offsetof(SocketCreator{}.StartTimeNs), 8},
		"ProcessID":   {unsafe.Offsetof(SocketCreator{}.ProcessID), 16},
		"ThreadID":    {unsafe.Offsetof(SocketCreator{}.ThreadID), 20},
		"UserID":      {unsafe.Offsetof(SocketCreator{}.UserID), 24},
		"Flags":       {unsafe.Offsetof(SocketCreator{}.Flags), 28},
		"Comm":        {unsafe.Offsetof(SocketCreator{}.Comm), 32},
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
	valid := CiliumEBPF.MapInfo{Type: CiliumEBPF.SkStorage, KeySize: 4, ValueSize: 48, MaxEntries: 0, Flags: bpfFlagNoPrealloc}
	for _, test := range []struct {
		name   string
		change func(*CiliumEBPF.MapInfo)
		valid  bool
	}{
		{"valid", func(*CiliumEBPF.MapInfo) {}, true},
		{"wrong map type", func(i *CiliumEBPF.MapInfo) { i.Type = CiliumEBPF.Hash }, false},
		{"wrong key size", func(i *CiliumEBPF.MapInfo) { i.KeySize = 8 }, false},
		{"short value", func(i *CiliumEBPF.MapInfo) { i.ValueSize = 40 }, false},
		{"long value", func(i *CiliumEBPF.MapInfo) { i.ValueSize = 56 }, false},
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
