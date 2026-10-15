//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"os"
	"sort"
	"strings"

	CiliumEBPF "github.com/cilium/ebpf"
)

// MapOccupancy describes one sing-ebpf map observed by an explicit diagnostic
// request. It is intentionally not collected by any runtime worker.
type MapOccupancy struct {
	ID         CiliumEBPF.MapID `json:"id"`
	Name       string           `json:"name"`
	Type       string           `json:"type"`
	MaxEntries uint32           `json:"max_entries"`
	KeySize    uint32           `json:"key_size"`
	ValueSize  uint32           `json:"value_size"`
	Flags      uint32           `json:"flags"`
	Entries    uint32           `json:"entries,omitempty"`
	Pressure   string           `json:"pressure"`
	Supported  bool             `json:"supported"`
	Error      string           `json:"error,omitempty"`
}

type MapOccupancyReport struct {
	Status string         `json:"status"`
	Maps   []MapOccupancy `json:"maps"`
	Error  string         `json:"error,omitempty"`
}

// InspectMapOccupancy enumerates only maps owned by sing-ebpf (sb_ prefix).
// It is deliberately an on-demand operation: callers should invoke it from a
// user-facing diagnostic command, never from a watchdog or data-plane path.
func InspectMapOccupancy() MapOccupancyReport {
	report := MapOccupancyReport{Status: "pass", Maps: make([]MapOccupancy, 0)}
	var id CiliumEBPF.MapID
	for {
		next, err := CiliumEBPF.MapGetNextID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			report.Error = err.Error()
			report.Status = "unknown"
			break
		}
		id = next
		m, err := CiliumEBPF.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, infoErr := m.Info()
		if infoErr != nil || info == nil || !strings.HasPrefix(info.Name, "sb_") {
			_ = m.Close()
			continue
		}
		item := MapOccupancy{
			ID: id, Name: info.Name, Type: info.Type.String(),
			MaxEntries: info.MaxEntries, KeySize: info.KeySize,
			ValueSize: info.ValueSize, Flags: info.Flags,
		}
		if !occupancySupported(info.Type) {
			item.Error = "map type does not support safe key iteration"
			item.Pressure = "not_applicable"
			report.Maps = append(report.Maps, item)
			_ = m.Close()
			continue
		}
		item.Supported = true
		item.Entries, err = countMapKeys(m, info.KeySize, info.MaxEntries)
		if err != nil {
			item.Error = err.Error()
		}
		item.Pressure = mapPressure(item.Name, item.Entries, item.MaxEntries, item.Error != "")
		report.Maps = append(report.Maps, item)
		_ = m.Close()
	}
	sort.Slice(report.Maps, func(i, j int) bool { return report.Maps[i].Name < report.Maps[j].Name })
	if report.Error == "" {
		report.Status = mapOccupancyStatus(report.Maps)
	}
	return report
}

func mapOccupancyStatus(maps []MapOccupancy) string {
	status := "pass"
	for _, item := range maps {
		if item.Pressure == "degraded" || item.Pressure == "recovery_failed" {
			return "degraded"
		} else if item.Pressure == "warning" {
			status = "warning"
		}
	}
	return status
}

func mapPressure(name string, entries, maxEntries uint32, failed bool) string {
	if failed {
		return "recovery_failed"
	}
	if configuredPolicyMap(name) {
		return "configured"
	}
	if maxEntries == 0 {
		return "unknown"
	}
	ratio := float64(entries) / float64(maxEntries)
	switch {
	case ratio >= 0.95:
		return "degraded"
	case ratio >= 0.85:
		return "warning"
	default:
		return "healthy"
	}
}

// configuredPolicyMap identifies maps whose capacity is derived from the
// current policy rather than used as a runtime state bound. Filling one of
// these maps is expected after the policy has been compiled; it must not be
// reported as runtime pressure. Maps with a fixed policy ceiling remain
// pressure-visible so an actual policy-capacity limit is still diagnosable.
func configuredPolicyMap(name string) bool {
	switch name {
	case
		"sb_cg_bypass_port",
		"sb_cg_uid",
		"sb_proc_uid",
		"sb_tc_uid",
		"sb_tc_insrc4", "sb_tc_insrc6",
		"sb_tc_exsrc4", "sb_tc_exsrc6",
		"sb_tc_insmac", "sb_tc_exsmac",
		"sb_tc_lport", "sb_tc_sport",
		"sb_sh_inmac", "sb_sh_exmac", "sb_sh_port":
		return true
	default:
		return false
	}
}

var errMapKeyIterationAborted = errors.New("map key iteration aborted")

func countMapKeys(m *CiliumEBPF.Map, keySize uint32, maxEntries uint32) (uint32, error) {
	key := make([]byte, keySize)
	next := make([]byte, keySize)
	err := m.NextKey(nil, &next)
	var entries uint32
	for err == nil {
		if entries >= maxEntries {
			return entries, errMapKeyIterationAborted
		}
		entries++
		copy(key, next)
		err = m.NextKey(key, &next)
	}
	if errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
		return entries, nil
	}
	return entries, err
}

func occupancySupported(typ CiliumEBPF.MapType) bool {
	switch typ {
	case CiliumEBPF.Hash, CiliumEBPF.LRUHash, CiliumEBPF.LPMTrie:
		return true
	default:
		return false
	}
}
