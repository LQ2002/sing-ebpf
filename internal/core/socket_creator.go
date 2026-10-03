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
// The fixed 48-byte layout is also defined in native/tc.bpf.c.
type SocketCreator struct {
	Cookie      uint64
	StartTimeNs uint64
	ProcessID   uint32
	ThreadID    uint32
	UserID      uint32
	Flags       uint32
	Comm        [16]byte
}

const SocketCreatorValid uint32 = 1 << 0

// IsValid requires a complete creator identity. UID zero is a valid root UID.
func (c SocketCreator) IsValid() bool {
	return c.Flags&SocketCreatorValid != 0 && c.Cookie != 0 && c.StartTimeNs != 0 && c.ProcessID != 0 && c.ThreadID != 0
}

func validateSocketCreatorMapInfo(info *CiliumEBPF.MapInfo) error {
	if info == nil || info.Type != CiliumEBPF.SkStorage || info.KeySize != 4 ||
		info.ValueSize != uint32(unsafe.Sizeof(SocketCreator{})) || info.MaxEntries != 0 || info.Flags != bpfFlagNoPrealloc {
		return E.New("invalid socket creator map: require SK_STORAGE key=4 value=48 max_entries=0 flags=NO_PREALLOC")
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
