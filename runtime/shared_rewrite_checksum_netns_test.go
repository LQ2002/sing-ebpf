//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// Read through a real UDP socket: a raw capture alone cannot distinguish a
// valid CHECKSUM_PARTIAL packet from a corrupt on-wire checksum.
func TestSharedRewriteUDPChecksumDeliveryIntegration(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "disabled"
		if partial {
			name = "partial_zero_seed"
		}
		t.Run(name, func(t *testing.T) {
			enterTestNetworkNamespace(t)
			self, peer := createTestVethPair(t, "sbcsum0", "sbcsum1")
			if err := os.WriteFile("/proc/sys/net/ipv4/conf/sbcsum0/route_localnet", []byte("1"), 0o644); err != nil {
				t.Fatal(err)
			}
			loopback, err := netlink.LinkByName("lo")
			if err != nil {
				t.Fatal(err)
			}
			if err = netlink.LinkSetUp(loopback); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if partial {
				// A zero checksum would make UDP accept the datagram as unchecked,
				// hiding an unadjusted partial seed. Reject that false positive.
				filter := []unix.SockFilter{
					{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 6},
					{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 0, Jf: 1},
					{Code: unix.BPF_RET | unix.BPF_K, K: 0},
					{Code: unix.BPF_RET | unix.BPF_K, K: 0xffff},
				}
				if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
					t.Fatal(err)
				}
			}
			if err = unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
				t.Fatal(err)
			}
			bound, err := unix.Getsockname(fd)
			if err != nil {
				t.Fatal(err)
			}
			timeout := unix.NsecToTimeval(time.Second.Nanoseconds())
			if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
				t.Fatal(err)
			}
			policy, err := commonEBPF.CompileActionPolicy(commonEBPF.ActionPolicy{EnableUDP: true, Shared: commonEBPF.ActionScope{Default: commonEBPF.DecisionIntercept}})
			if err != nil {
				t.Fatal(err)
			}
			backend, err := commonEBPF.PrepareSharedPacketRewrite(nil, commonEBPF.SharedPacketRewriteConfig{
				ListenerPort: uint16(bound.(*unix.SockaddrInet4).Port), EnableUDP: true,
				RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"), Policy: policy,
				MapCapacity: commonEBPF.SharedPacketRewriteMapCapacity{Proxy: 64, Bypass: 64}, UDPTimeout: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			attachment, err := attachSharedRewriteInterface(self, backend, 2)
			if err != nil {
				t.Fatal(err)
			}
			defer attachment.Close()
			if err = backend.Enable(); err != nil {
				t.Fatal(err)
			}
			payload := []byte("udp-payload")
			// The folded pseudo-header sum is 0xffff (negative zero), making
			// zero an equivalent partial seed. This is not checksum-disabled.
			packet := buildEthernetIPv4UDPPacket(self.Attrs().HardwareAddr, peer.Attrs().HardwareAddr,
				net.ParseIP("10.250.0.2"), net.ParseIP("203.0.41.223"), 53000, 9681, payload)
			pseudo := make([]byte, 12)
			copy(pseudo[:8], packet[26:34])
			pseudo[9] = unix.IPPROTO_UDP
			binary.BigEndian.PutUint16(pseudo[10:], uint16(len(packet)-34))
			if internetChecksum(pseudo, -1) != 0 {
				t.Fatal("fixture does not have a zero-equivalent partial seed")
			}
			sender := openRawLinkLayerSocket(t, peer.Attrs().Index, unix.ETH_P_IP, time.Second)
			if partial {
				if err = unix.SetsockoptInt(sender, unix.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
					t.Fatal(err)
				}
				header := make([]byte, 10) // struct virtio_net_hdr, native byte order
				header[0] = 1              // VIRTIO_NET_HDR_F_NEEDS_CSUM
				binary.NativeEndian.PutUint16(header[6:8], 34)
				binary.NativeEndian.PutUint16(header[8:10], 6)
				packet = append(header, packet...)
			}
			if _, err = unix.Write(sender, packet); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 1500)
			n, _, err := unix.Recvfrom(fd, data, 0)
			if err != nil {
				t.Fatal(err)
			}
			if string(data[:n]) != string(payload) {
				t.Fatalf("unexpected payload: %q", data[:n])
			}
		})
	}
}
