//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestSharedPacketRewriteUDPChecksumIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify UDP rewrite checksums in both directions")
	for _, family := range []string{"IPv4", "IPv6"} {
		for _, disabled := range []bool{false, true} {
			if family == "IPv6" && disabled {
				continue // IPv6 UDP requires a checksum.
			}
			name := family + "/enabled"
			if disabled {
				name = family + "/disabled"
			}
			t.Run(name, func(t *testing.T) {
				policy, err := CompileActionPolicy(ActionPolicy{EnableUDP: true, Shared: ActionScope{Default: DecisionIntercept}})
				if err != nil {
					t.Fatal(err)
				}
				backend, err := PrepareSharedPacketRewrite(nil, SharedPacketRewriteConfig{
					ListenerPort: 65531, EnableUDP: true, Policy: policy,
					RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
					RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
					MapCapacity:  DefaultSharedPacketRewriteMapCapacity(), UDPTimeout: time.Minute,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = backend.Close() })
				if err = backend.Enable(); err != nil {
					t.Fatal(err)
				}
				client, remote := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.10")
				if family == "IPv6" {
					client, remote = netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8::20")
				}
				packet := checksumTestUDPPacket(client, remote, 53000, 9681, disabled)
				action, output := runTCProgram(t, backend.runtime.programs[sharedNetworkProgramIngress], packet)
				if action == testTCActShot {
					t.Fatal("ingress dropped packet")
				}
				checkTestUDPChecksum(t, output, disabled)
				var token netip.Addr
				if client.Is4() {
					token = netip.AddrFrom4([4]byte(output[30:34]))
				} else {
					token = netip.AddrFrom16([16]byte(output[38:54]))
				}
				if token == remote {
					t.Fatal("ingress did not rewrite destination")
				}
				reply := checksumTestUDPPacket(token, client, 65531, 53000, disabled)
				action, output = runTCProgram(t, backend.runtime.programs[sharedNetworkProgramEgress], reply)
				if action == testTCActShot {
					t.Fatal("egress dropped packet")
				}
				checkTestUDPChecksum(t, output, disabled)
				want := checksumTestUDPPacket(remote, client, 9681, 53000, disabled)
				if string(output) != string(want) {
					t.Fatalf("reply differs from original tuple packet: got %x, want %x", output, want)
				}
			})
		}
	}
}

func checksumTestUDPPacket(source, destination netip.Addr, sourcePort, destinationPort uint16, disabled bool) []byte {
	var packet []byte
	if source.Is4() {
		packet = testIPv4TCPPacket(source, destination, sourcePort, destinationPort)
		packet[23] = ProtocolUDP
	} else {
		packet = testIPv6TCPPacket(source, destination, sourcePort, destinationPort, nil)
		packet[20] = ProtocolUDP
	}
	// Reuse the 20-byte transport allocation for UDP and an odd-length payload.
	packet = packet[:len(packet)-1]
	offset, pseudo := checksumTestUDPPseudo(packet)
	udp := packet[offset:]
	clear(udp[4:])
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], "udp-payload")
	if source.Is4() {
		binary.BigEndian.PutUint16(packet[16:18], uint16(len(packet)-14))
		binary.BigEndian.PutUint16(packet[24:26], checksumTestSum(packet[14:34]))
	} else {
		binary.BigEndian.PutUint16(packet[18:20], uint16(len(udp)))
	}
	if !disabled {
		checksum := checksumTestSum(append(pseudo, udp...))
		if checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(udp[6:8], checksum)
	}
	return packet
}

func checksumTestUDPPseudo(packet []byte) (int, []byte) {
	if packet[14]>>4 == 4 {
		pseudo := make([]byte, 12)
		copy(pseudo[:8], packet[26:34])
		pseudo[9] = ProtocolUDP
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(packet)-34))
		return 34, pseudo
	}
	pseudo := make([]byte, 40)
	copy(pseudo[:32], packet[22:54])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(packet)-54))
	pseudo[39] = ProtocolUDP
	return 54, pseudo
}

func checksumTestSum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func checkTestUDPChecksum(t *testing.T, packet []byte, disabled bool) {
	t.Helper()
	offset, pseudo := checksumTestUDPPseudo(packet)
	if packet[14]>>4 == 4 && checksumTestSum(packet[14:34]) != 0 {
		t.Fatal("invalid IPv4 header checksum")
	}
	checksum := binary.BigEndian.Uint16(packet[offset+6 : offset+8])
	if disabled {
		if checksum != 0 {
			t.Fatalf("disabled UDP checksum changed to %04x", checksum)
		}
	} else if checksum == 0 || checksumTestSum(append(pseudo, packet[offset:]...)) != 0 {
		t.Fatalf("invalid UDP checksum: %04x", checksum)
	}
}
