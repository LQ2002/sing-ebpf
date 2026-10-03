//go:build with_ebpf && (linux || android)

package core

import (
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

// SocketCreator is an immutable socket-creation snapshot shared with the
// producer through SK_STORAGE. StartTimeNs is the group leader birth time;
// it is not a unique task or exec incarnation ID (exec can preserve it).
// UserID is the creator's UID, independent of the socket's mutable billing UID.
// The fixed 64-byte (v2) layout is also defined in native/tc.bpf.c.
//
// ProcessNameHash is FNV-1a 64 over the creating process's argv[0] read at
// socket creation; on Android that is the ActivityManager process record name
// (zygote sets it before app code runs). ExeInode is the inode number of the
// creating process's executable. Each is meaningful only with its own flag:
// the producer cannot read them for every task.
type SocketCreator struct {
	Cookie          uint64
	StartTimeNs     uint64
	ProcessID       uint32
	ThreadID        uint32
	UserID          uint32
	Flags           uint32
	Comm            [16]byte
	ProcessNameHash uint64
	ExeInode        uint64
}

const (
	SocketCreatorValid     uint32 = 1 << 0
	SocketCreatorNameValid uint32 = 1 << 1
	SocketCreatorExeValid  uint32 = 1 << 2
)

// HasProcessName reports whether ProcessNameHash was recorded.
func (c SocketCreator) HasProcessName() bool {
	return c.Flags&SocketCreatorNameValid != 0
}

// HasExecutable reports whether ExeInode was recorded.
func (c SocketCreator) HasExecutable() bool {
	return c.Flags&SocketCreatorExeValid != 0
}

// IsValid requires a complete creator identity. UID zero is a valid root UID.
func (c SocketCreator) IsValid() bool {
	return c.Flags&SocketCreatorValid != 0 && c.Cookie != 0 && c.StartTimeNs != 0 && c.ProcessID != 0 && c.ThreadID != 0
}

func validateSocketCreatorMapInfo(info *CiliumEBPF.MapInfo) error {
	if info == nil || info.Type != CiliumEBPF.SkStorage || info.KeySize != 4 ||
		info.ValueSize != uint32(unsafe.Sizeof(SocketCreator{})) || info.MaxEntries != 0 || info.Flags != bpfFlagNoPrealloc {
		return E.New("invalid socket creator map: require SK_STORAGE key=4 value=64 max_entries=0 flags=NO_PREALLOC")
	}
	return nil
}

func validateSocketCreatorMap(creatorMap *CiliumEBPF.Map) error {
	info, err := creatorMap.Info()
	if err != nil {
		return E.Cause(err, "inspect socket creator map")
	}
	return validateSocketCreatorMapInfo(info)
}

// validateCookieTagMapInfo accepts Android netd's cookie_tag_map layout:
// HASH, key u64 socket cookie, value UidTagValue{u32 uid; u32 tag}
// (Connectivity bpf/netd). The entry count is netd's choice and not checked.
func validateCookieTagMapInfo(info *CiliumEBPF.MapInfo) error {
	if info == nil || info.Type != CiliumEBPF.Hash || info.KeySize != 8 || info.ValueSize != 8 {
		return E.New("invalid cookie tag map: require HASH key=8 value=8")
	}
	return nil
}

func validateCookieTagMap(cookieTagMap *CiliumEBPF.Map) error {
	info, err := cookieTagMap.Info()
	if err != nil {
		return E.Cause(err, "inspect cookie tag map")
	}
	return validateCookieTagMapInfo(info)
}
