// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "abi.h"
#include "bpf_compat.h"
#include "force_intercept_policy.h"
#include "private_address.h"

#include <linux/bpf.h>

#define BPF_ANY 0U
#define BPF_F_CURRENT_NETNS (-1ULL)
#define BPF_F_INGRESS (1ULL << 0)
#define BPF_TCP_LISTEN 10U
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC (-1)

#define ETH_P_IP_VALUE 0x0800U
#define ETH_P_IPV6_VALUE 0x86ddU
#define ETH_P_8021Q_VALUE 0x8100U
#define ETH_P_8021AD_VALUE 0x88a8U
#define AF_INET_VALUE 2U
#define AF_INET6_VALUE 10U
#define IPPROTO_TCP_VALUE 6U
#define IPPROTO_UDP_VALUE 17U
#define IPPROTO_HOPOPTS_VALUE 0U
#define IPPROTO_ROUTING_VALUE 43U
#define IPPROTO_FRAGMENT_VALUE 44U
#define IPPROTO_AH_VALUE 51U
#define IPPROTO_DSTOPTS_VALUE 60U
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fffU
#define IPV4_FRAGMENT_MORE 0x2000U
#define IPV6_FRAGMENT_OFFSET_MASK 0xfff8U
#define IPV6_FRAGMENT_MORE 0x0001U

#define SB_TC_FLAG_IPV4 (1U << 0)
#define SB_TC_FLAG_LOCAL_IPV6 (1U << 1)
#define SB_TC_FLAG_TCP (1U << 2)
#define SB_TC_FLAG_UDP (1U << 3)
#define SB_TC_FLAG_UID_POLICY (1U << 4)
#define SB_TC_FLAG_UID_DEFAULT_BYPASS (1U << 5)
#define SB_TC_FLAG_LOCAL_BYPASS_PRIVATE (1U << 6)
#define SB_TC_FLAG_SHARED_BYPASS_PRIVATE (1U << 7)
#define SB_TC_FLAG_BYPASS_IPV4 (1U << 8)
#define SB_TC_FLAG_BYPASS_IPV6 (1U << 9)
#define SB_TC_FLAG_LOCAL_BYPASS_IPV4 SB_TC_FLAG_BYPASS_IPV4
#define SB_TC_FLAG_LOCAL_BYPASS_IPV6 SB_TC_FLAG_BYPASS_IPV6
#define SB_TC_FLAG_FORCE_INTERCEPT_IPV4 (1U << 10)
#define SB_TC_FLAG_FORCE_INTERCEPT_IPV6 (1U << 11)
#define SB_TC_FLAG_INCLUDE_SOURCE (1U << 12)
#define SB_TC_FLAG_EXCLUDE_SOURCE (1U << 13)
#define SB_TC_FLAG_INCLUDE_SOURCE_MAC (1U << 14)
#define SB_TC_FLAG_EXCLUDE_SOURCE_MAC (1U << 15)
#define SB_TC_FLAG_HOST_IPV4 (1U << 16)
#define SB_TC_FLAG_HOST_IPV6 (1U << 17)
#define SB_TC_FLAG_SHARED_IPV6 (1U << 18)
#define SB_TC_FLAG_LOCAL_BYPASS_PORT (1U << 20)
#define SB_TC_FLAG_SHARED_BYPASS_PORT (1U << 21)
#define SB_TC_FLAG_SHARED_BYPASS_IPV4 (1U << 22)
#define SB_TC_FLAG_SHARED_BYPASS_IPV6 (1U << 23)

#define SB_TC_SOCKET_POLICY_BYPASS 1U
#define SB_TC_SOCKET_POLICY_INTERCEPT 2U

#define SB_TC_DNS_HIJACK 0U
#define SB_TC_DNS_RESPECT_POLICY 1U
#define SB_TC_DNS_OFF 2U

#define SB_TC_LISTENER_TCP4 0U
#define SB_TC_LISTENER_TCP6 1U
#define SB_TC_LISTENER_COUNT 2U

#define SB_TC_PATH_SHARED 1U
#define SB_TC_PATH_DELIVERY 2U
#define SB_TC_PATH_SOURCE_MAC_VALID 0x80U

// sb_tc_assign_value.identity_flags。两位总是一起置位或一起清零：
// bpf_get_socket_uid 和 bpf_skb_cgroup_id 在内核里（net/core/filter.c，v6.12）
// 用的是同一个判断——sk_to_full_sk(skb->sk) 之后必须是 full socket——不满足时
// 前者返回 overflowuid、后者返回 0。所以 cgroup id 非 0 就同时证明 uid 有效，
// 不需要拿 overflowuid（65534，可能是真实 uid）去猜。分成两位只是让读取方不必
// 知道这层关系。
#define SB_TC_IDENTITY_UID_VALID (1U << 0)
#define SB_TC_IDENTITY_CGROUP_VALID (1U << 1)
#define SB_TC_IDENTITY_VALID (SB_TC_IDENTITY_UID_VALID | SB_TC_IDENTITY_CGROUP_VALID)
// Independent of UID/cgroup validity: a valid creator or a confirmed missing
// entry from a full socket has been observed. Invalid non-null entries retry.
#define SB_TC_IDENTITY_CREATOR_CHECKED (1U << 2)
// The netd cookie tag lookup ran (CHECKED) and found an entry (VALID). Set
// only by the creator variants, at the same moment the creator is first read.
#define SB_TC_IDENTITY_CHARGE_CHECKED (1U << 3)
#define SB_TC_IDENTITY_CHARGE_VALID (1U << 4)

#define SB_TC_STAT_SOCKET_LOOKUP_FAILURE 0U
#define SB_TC_STAT_SK_ASSIGN_FAILURE 1U
#define SB_TC_STAT_ASSIGNMENT_UPDATE_FAILURE 2U
#define SB_TC_STAT_LOCAL_FRAGMENT_PASS 3U
#define SB_TC_STAT_SHARED_FRAGMENT_PASS 4U
#define SB_TC_STAT_COUNT 5U

struct sb_tc_control {
    __u32 enabled;
    __u32 flags;
    __u32 delivery_ifindex;
    __u32 routing_mark;
    __u16 listener_port;
    __u16 local_dns_mode;
    __u16 shared_dns_mode;
    __u8 delivery_mac[6];
    __u16 reserved;
    __u8 force_intercept_ipv4_prefix[4];
    __u8 force_intercept_ipv4_mask[4];
    __u8 force_intercept_ipv6_prefix[16];
    __u8 force_intercept_ipv6_mask[16];
    // policy_generation 是判定缓存的失效凭据。用户态在每次写 control 之前递增
    // 它，而所有策略变更都汇流到那一次写（见 internal/core/tc.go 的
    // updateControlLocked），所以缓存下来的判定只要代号对不上就作废。0 保留为
    // "没有缓存"，永远不会被用作一个有效代号。
    __u32 policy_generation;
    // activity_epoch is the current TC assignment activity period. Userspace
    // advances it from SweepAssignments (at most once per second) and records
    // when each period began; assign_* stamp it into the entries they pass.
    // An entry still stamped with period e saw no packet after period e + 1
    // began, which is how the sweep proves idleness without a per-packet
    // clock read: upstream stamps ktime_get_ns() into every assignment on
    // every packet, which costs a helper call and a store into a shared
    // entry per packet. Here an entry is written at most once per period.
    // Advancing it never bumps policy_generation, so cached verdicts survive.
    __u32 activity_epoch;
};

struct sb_tc_uid_key {
    __u32 prefixlen;
    __u8 uid[4];
};

struct sb_tc_ipv4_lpm_key {
    __u32 prefixlen;
    __u8 address[4];
};

struct sb_tc_ipv6_lpm_key {
    __u32 prefixlen;
    __u8 address[16];
};

struct sb_tc_ipv4_key {
    __u8 address[4];
};

struct sb_tc_ipv6_key {
    __u8 address[16];
};

struct sb_tc_mac_key {
    __u8 address[6];
    __u8 reserved[2];
};

struct sb_tc_port_key {
    __u8 protocol;
    __u8 reserved;
    __u16 port;
};

struct sb_tc_assign_key {
    __u8 family;
    __u8 protocol;
    __u16 source_port;
    __u16 destination_port;
    __u16 reserved;
    __u32 interface_index;
    __u8 source_addr[16];
    __u8 destination_addr[16];
};

// Fixed shared ABI with the socket creator producer (v2, 64 bytes). The
// creator UID is never replaced by the socket's mutable billing UID. No CLONE
// storage: a child socket must acquire its own creation snapshot rather than
// inherit one.
//
// v2 adds two creation-time facts so userspace needs no /proc read for them:
// process_name_hash is FNV-1a 64 over the creating process's argv[0] (the
// ActivityManager process record name: zygote's setArgV0 runs before any app
// code), and exe_inode is the inode of its executable. Each has its own
// validity bit because the producer cannot always read them (no mm for kernel
// threads, a user-memory fault while reading argv).
#define SB_SOCKET_CREATOR_VALID (1U << 0)
#define SB_SOCKET_CREATOR_NAME_VALID (1U << 1)
#define SB_SOCKET_CREATOR_EXE_VALID (1U << 2)
// Set by the producer when the argv[0] it hashed may be a prefix of the real
// process name: the string filled the whole argument block (zygote's setArgv0
// strlcpy's into its original argv block, 99 or 78 bytes measured on the
// device) or the 128-byte read buffer. Bits 8-15 hold the hashed byte count.
// TC only copies these bits; userspace interprets them.
#define SB_SOCKET_CREATOR_NAME_TRUNCATED (1U << 3)
#define SB_SOCKET_CREATOR_NAME_LENGTH_SHIFT 8
struct sb_socket_creator {
    __u64 cookie;
    __u64 start_time_ns;
    __u32 process_id;
    __u32 thread_id;
    __u32 user_id;
    __u32 flags;
    __u8 comm[16];
    __u64 process_name_hash;
    __u64 exe_inode;
};
_Static_assert(sizeof(struct sb_socket_creator) == 64, "sb_socket_creator ABI size");
_Static_assert(__builtin_offsetof(struct sb_socket_creator, process_name_hash) == 48, "creator name hash offset");
_Static_assert(__builtin_offsetof(struct sb_socket_creator, exe_inode) == 56, "creator exe inode offset");
_Static_assert(__builtin_offsetof(struct sb_socket_creator, cookie) == 0, "creator cookie offset");
_Static_assert(__builtin_offsetof(struct sb_socket_creator, start_time_ns) == 8, "creator start offset");
_Static_assert(__builtin_offsetof(struct sb_socket_creator, process_id) == 16, "creator pid offset");
_Static_assert(__builtin_offsetof(struct sb_socket_creator, thread_id) == 20, "creator tid offset");
_Static_assert(__builtin_offsetof(struct sb_socket_creator, user_id) == 24, "creator uid offset");
_Static_assert(__builtin_offsetof(struct sb_socket_creator, flags) == 28, "creator flags offset");
_Static_assert(__builtin_offsetof(struct sb_socket_creator, comm) == 32, "creator comm offset");

INLINE bool socket_creator_valid(const struct sb_socket_creator *creator, __u64 cookie) {
    return (creator->flags & SB_SOCKET_CREATOR_VALID) != 0U &&
        creator->cookie != 0U && creator->cookie == cookie && creator->start_time_ns != 0U &&
        creator->process_id != 0U && creator->thread_id != 0U;
}

struct sb_tc_assign_value {
    __u64 socket_cookie;
    __u32 ifindex;
    __u8 source_mac[6];
    __u8 path;
    __u8 source_mac_valid;
    // 以下是本机出站路径记录的 socket 身份，只在“身份采集”程序变体里填写
    // （见 record_local_socket）。shared 路径的流量不是本机 socket 发的，
    // 这三个字段保持 0，不伪造本机身份；delivery 路径原样保留本机路径写下的值。
    //
    // socket_uid 是 sk->sk_uid，即 socket 的“记账 UID”：netd 会把替应用发的
    // DNS socket fchown 成应用的 UID，所以它不一定是创建进程的 UID。
    // socket_cgroup_id 是 socket 创建时所在的 cgroup v2 id（cgroup_sk_alloc，
    // kernel/cgroup/cgroup.c），之后进程迁移 cgroup 也不会改变它；Android 上每个
    // 进程有自己的 /uid_X/pid_Y cgroup，所以它能把 socket 定位到创建它的进程。
    __u32 socket_uid;
    __u64 socket_cgroup_id;
    __u32 identity_flags;
    // activity_epoch: see sb_tc_control.activity_epoch. 0 means not yet
    // stamped (an entry only the local path has written); the sweep never
    // removes those. It is not part of the "changed" comparison.
    __u32 activity_epoch;
    struct sb_socket_creator creator;
    // netd's cookie_tag_map entry for this socket, read once together with the
    // creator (SB_TC_IDENTITY_CHARGE_*). charge_uid is the UID netd bills the
    // socket to. A service sending on an app's behalf (DownloadProvider, GMS)
    // tags its socket with that app's UID; netd only accepts a charge UID that
    // differs from the caller's when the caller holds UPDATE_DEVICE_STATS
    // (Connectivity bpf/netd/BpfHandler.cpp tagSocket). It names the
    // requester, never the sender, so userspace must not route by it. A tag
    // applied after the first recorded packet is not seen.
    __u32 charge_uid;
    __u32 charge_tag;
};

_Static_assert(sizeof(struct sb_tc_control) == 80, "sb_tc_control ABI size");
_Static_assert(__builtin_offsetof(struct sb_tc_control, activity_epoch) == 76,
    "sb_tc_control activity_epoch ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_control, delivery_ifindex) == 8,
    "sb_tc_control delivery_ifindex ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_control, routing_mark) == 12,
    "sb_tc_control routing_mark ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_control, listener_port) == 16,
    "sb_tc_control listener_port ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_control, force_intercept_ipv6_mask) == 54,
    "sb_tc_control force_intercept_ipv6_mask ABI offset");
// 本机出站判定的缓存值。判定只取决于目的地、协议、uid 和当前策略，对一条已连接
// 的 TCP socket 来说这些在其生命周期内都不变，所以整条判定链每个 socket 只需要
// 跑一次而不是每个包跑一次。最贵的那一环是 bypass_destination 的 LPM trie 遍历，
// 它没有内联形式，要沿前缀位逐层下降。
struct sb_tc_socket_verdict {
    __u32 generation;
    __u8 verdict;
    __u8 reserved[3];
};
_Static_assert(sizeof(struct sb_tc_socket_verdict) == 8, "sb_tc_socket_verdict ABI size");

// 判定缓存整体按一个 64 位字读写。同一个 TCP socket 的包可以同时在两个 CPU 上
// 过 TC（用户线程发送和软中断里的重传/ACK），如果分两次写 generation 和
// verdict，交错之后可能留下“新代号＋旧判定”。对齐的 8 字节访问在 arm64 和
// x86-64 上都是单次拷贝原子的；socket 本地存储的数据区按 8 字节对齐
// （struct bpf_local_storage_data 的 data[] __aligned(8)）。
union sb_tc_socket_verdict_word {
    struct sb_tc_socket_verdict fields;
    __u64 word;
};
_Static_assert(sizeof(union sb_tc_socket_verdict_word) == 8, "sb_tc_socket_verdict_word size");

_Static_assert(sizeof(struct sb_tc_assign_key) == 44, "sb_tc_assign_key ABI size");
_Static_assert(sizeof(struct sb_tc_assign_value) == 112, "sb_tc_assign_value ABI size");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, charge_uid) == 104, "assignment charge uid offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, charge_tag) == 108, "assignment charge tag offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, creator) == 40, "assignment creator offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, socket_cookie) == 0,
    "sb_tc_assign_value socket_cookie ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, ifindex) == 8,
    "sb_tc_assign_value ifindex ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, source_mac) == 12,
    "sb_tc_assign_value source_mac ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, path) == 18,
    "sb_tc_assign_value path ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, source_mac_valid) == 19,
    "sb_tc_assign_value source_mac_valid ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, socket_uid) == 20,
    "sb_tc_assign_value socket_uid ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, socket_cgroup_id) == 24,
    "sb_tc_assign_value socket_cgroup_id ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, identity_flags) == 32,
    "sb_tc_assign_value identity_flags ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, activity_epoch) == 36,
    "sb_tc_assign_value activity_epoch ABI offset");

struct ethernet_header {
    __u8 destination[6];
    __u8 source[6];
    __be16 protocol;
};

struct vlan_header {
    __be16 tci;
    __be16 protocol;
};

struct ipv4_header {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __be16 total_length;
    __be16 id;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __sum16 checksum;
    __be32 source;
    __be32 destination;
};

struct ipv6_header {
    __be32 version_flow;
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

struct transport_ports {
    __be16 source;
    __be16 destination;
};

struct ipv6_extension_header {
    __u8 next_header;
    __u8 length;
};

struct ipv6_fragment_header {
    __u8 next_header;
    __u8 reserved;
    __be16 offset_flags;
    __be32 identification;
};

#define MAP(name, key, value, map_type, entries) \
    struct bpf_map_def SEC("maps") name = { \
        .type = map_type, .key_size = sizeof(key), .value_size = sizeof(value), \
        .max_entries = entries, \
    }

MAP(tc_control, __u32, struct sb_tc_control, BPF_MAP_TYPE_ARRAY, 1U);
MAP(tc_listener_sockets, __u32, __u32, BPF_MAP_TYPE_SOCKMAP, SB_TC_LISTENER_COUNT);
MAP(tc_assignment, struct sb_tc_assign_key, struct sb_tc_assign_value, BPF_MAP_TYPE_LRU_HASH, 65536U);
MAP(tc_stats, __u32, __u64, BPF_MAP_TYPE_PERCPU_ARRAY, SB_TC_STAT_COUNT);
// tc_assign_generation 是 tc_assignment 的写入代号：本文件每写一次 tc_assignment
// 就在写完之后加一（bump_assignment_generation）。用户态把这个单元素数组以
// BPF_F_MMAPABLE 映射进内存，不经系统调用就能读到当前代号，据此判断自己缓存的
// 分配结果是否可能已过期：代号没变，就说明从它读取代号之后没有任何分配被写过。
//
// 写入与加一都发生在引起它的那个包被 sk_assign 送进监听 socket 之前，所以用户态
// 读到这个包时一定也能看到这次加一。代号只增不减，跨 CPU 用原子加。
MAP(tc_assign_generation, __u32, __u64, BPF_MAP_TYPE_ARRAY, 1U);
// Borrowed only for the opt-in local creator variants; the default loader does
// not create or reference this map. The producer owns the sb_sk_creator map.
struct bpf_map_def SEC("maps") socket_creators = {
    .type = BPF_MAP_TYPE_SK_STORAGE,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct sb_socket_creator),
    .max_entries = 0U,
    .map_flags = 1U, // BPF_F_NO_PREALLOC, explicitly without BPF_F_CLONE.
};
// netd's cookie_tag_map layout (Connectivity bpf/netd: HASH, key u64 socket
// cookie, value UidTagValue{u32 uid; u32 tag}). Referenced only by the creator
// variants. The loader replaces it with the pinned netd map when one is
// supplied and otherwise binds an empty one-entry placeholder, so a lookup
// simply misses and the charge stays unknown.
struct sb_netd_uid_tag {
    __u32 uid;
    __u32 tag;
};
_Static_assert(sizeof(struct sb_netd_uid_tag) == 8, "netd UidTagValue size");
MAP(netd_cookie_tags, __u64, struct sb_netd_uid_tag, BPF_MAP_TYPE_HASH, 1U);
// tc_self_sockets 不是普通哈希表，而是挂在 socket 本身上的本地存储。
// 这样做的理由是回收：按 socket cookie 索引的哈希表没有任何东西在 socket
// 关闭时删除对应条目（用户态注册路径尤其如此，见 internal/core/self_bypass.go
// 的 RegisterSocket），只能靠 LRU 淘汰兜底，于是一条长连接的 cookie 可能在
// socket 还活着的时候被新条目挤掉，下一个包就重新落进拦截路径。本地存储随
// socket 释放自动回收，这一类问题从根上不存在。
//
// 老式 bpf_map_def 就能声明这种 map（key_size 与 max_entries 必须为 0），
// 不需要 BTF 式的 map 定义——这一点很关键，因为构建流程会用 llvm-objcopy
// 把 .BTF 段从对象里剥掉，见 Makefile 的 generate 目标。
// 与 tc_self_sockets 分开而不是并进同一个值结构，是为了不动那张表的 ABI：
// 它由用户态按 fd 写、由 cgroup 钩子读写，还被 cgroup_socket_bypass 共用。
// 命中缓存时这张表是唯一被读的 map，所以分成两张并不会让热路径多一次查找。
struct bpf_map_def SEC("maps") tc_local_verdict = {
    .type = BPF_MAP_TYPE_SK_STORAGE,
    .key_size = 0U,
    .value_size = sizeof(struct sb_tc_socket_verdict),
    .max_entries = 0U,
};

struct bpf_map_def SEC("maps") tc_self_sockets = {
    .type = BPF_MAP_TYPE_SK_STORAGE,
    .key_size = 0U,
    .value_size = sizeof(__u32),
    .max_entries = 0U,
};
MAP(tc_uid_policy, struct sb_tc_uid_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_local_bypass_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_local_bypass_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_shared_bypass_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_shared_bypass_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_include_source_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_include_source_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_exclude_source_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_exclude_source_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_include_source_mac, struct sb_tc_mac_key, __u8, BPF_MAP_TYPE_HASH, 1024U);
MAP(tc_exclude_source_mac, struct sb_tc_mac_key, __u8, BPF_MAP_TYPE_HASH, 1024U);
MAP(tc_host_ipv4, struct sb_tc_ipv4_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
MAP(tc_host_ipv6, struct sb_tc_ipv6_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
MAP(tc_local_bypass_port, struct sb_tc_port_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
MAP(tc_shared_bypass_port, struct sb_tc_port_key, __u8, BPF_MAP_TYPE_HASH, 4096U);

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u32 (*get_socket_uid)(void *ctx) = (void *)BPF_FUNC_get_socket_uid;
static __u64 (*get_socket_cookie)(void *ctx) = (void *)BPF_FUNC_get_socket_cookie;
static __u64 (*skb_cgroup_id)(void *ctx) = (void *)BPF_FUNC_skb_cgroup_id;
static long (*redirect)(int ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static long (*skb_store_bytes)(void *ctx, __u32 offset, const void *from, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
static long (*skb_change_head)(void *ctx, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_change_head;
static struct bpf_sock *(*skc_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple,
    __u32 tuple_size, __u64 netns, __u64 flags) = (void *)BPF_FUNC_skc_lookup_tcp;
static struct bpf_sock *(*sk_lookup_udp)(void *ctx, struct bpf_sock_tuple *tuple,
    __u32 tuple_size, __u64 netns, __u64 flags) = (void *)BPF_FUNC_sk_lookup_udp;
static long (*sk_assign)(void *ctx, struct bpf_sock *socket, __u64 flags) =
    (void *)BPF_FUNC_sk_assign;
static void (*sk_release)(struct bpf_sock *socket) = (void *)BPF_FUNC_sk_release;
static void *(*sk_storage_get)(void *map, void *socket, void *value, __u64 flags) =
    (void *)BPF_FUNC_sk_storage_get;

// BPF_LOCAL_STORAGE_GET_F_CREATE：条目不存在时按传入的值新建。
#define SB_TC_LOCAL_STORAGE_CREATE 1ULL

INLINE void increment_stat(__u32 index) {
    if (index >= SB_TC_STAT_COUNT) return;
    __u64 *value = map_lookup(&tc_stats, &index);
    if (value != 0) *value += 1U;
}

INLINE void bump_assignment_generation(void) {
    __u32 index = 0U;
    __u64 *generation = map_lookup(&tc_assign_generation, &index);
    if (generation != 0) __sync_fetch_and_add(generation, 1U);
}

INLINE __u16 network_order16(__u16 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap16(value);
#else
    return value;
#endif
}

INLINE __u32 network_order32(__u32 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value;
#endif
}

INLINE void copy_address(__u8 destination[16], const __u8 source[16], __u32 size) {
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < 16U; ++index) {
        destination[index] = index < size ? source[index] : 0U;
    }
}

INLINE const struct sb_tc_control *load_control(void) {
    __u32 zero = 0U;
    return map_lookup(&tc_control, &zero);
}

INLINE bool protocol_enabled(const struct sb_tc_control *control, __u8 protocol) {
    if (protocol == IPPROTO_TCP_VALUE) return (control->flags & SB_TC_FLAG_TCP) != 0U;
    if (protocol == IPPROTO_UDP_VALUE) return (control->flags & SB_TC_FLAG_UDP) != 0U;
    return false;
}

INLINE bool service_port(__u8 protocol, __u16 source, __u16 destination) {
    if (protocol != IPPROTO_UDP_VALUE) return false;
    return source == 67U || source == 68U || source == 546U || source == 547U ||
        destination == 67U || destination == 68U || destination == 546U || destination == 547U;
}

INLINE bool uid_bypassed(struct __sk_buff *skb, const struct sb_tc_control *control) {
    if ((control->flags & SB_TC_FLAG_UID_POLICY) == 0U) return false;
    __u32 uid = network_order32(get_socket_uid(skb));
    struct sb_tc_uid_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.uid, &uid, sizeof(uid));
    bool matched = map_lookup(&tc_uid_policy, &key) != 0;
    return (control->flags & SB_TC_FLAG_UID_DEFAULT_BYPASS) != 0U ? !matched : matched;
}

// skb->sk 的 verifier 类型是 sock_common_or_null，必须先判空才能传给
// helper，否则加载时报 "R2 type=sock_common_or_null expected=sock_common"。
// 本机出站路径上 skb->sk 通常是有的——同一处原本就在调 bpf_get_socket_cookie，
// 那个 helper 同样依赖 skb->sk——但转发和无主流量会走到空指针分支。
INLINE __u32 socket_metadata(struct __sk_buff *skb) {
    if (skb->sk == 0) return 0U;
    __u32 *metadata = sk_storage_get(&tc_self_sockets, skb->sk, 0, 0U);
    return metadata != 0 ? *metadata : 0U;
}

INLINE bool port_bypassed(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, bool shared) {
    __u32 flag = shared ? SB_TC_FLAG_SHARED_BYPASS_PORT : SB_TC_FLAG_LOCAL_BYPASS_PORT;
    if ((control->flags & flag) == 0U) return false;
    struct sb_tc_port_key key = {.protocol = flow->protocol, .port = flow->destination_port};
    if (shared) return map_lookup(&tc_shared_bypass_port, &key) != 0;
    return map_lookup(&tc_local_bypass_port, &key) != 0;
}

INLINE bool dns_selected(__u8 protocol, __u16 destination_port, __u16 mode) {
    if ((protocol != IPPROTO_TCP_VALUE && protocol != IPPROTO_UDP_VALUE) || destination_port != 53U) return false;
    return mode == SB_TC_DNS_HIJACK;
}

INLINE bool dns_bypassed(__u8 protocol, __u16 destination_port, __u16 mode) {
    return (protocol == IPPROTO_TCP_VALUE || protocol == IPPROTO_UDP_VALUE) &&
        destination_port == 53U && mode == SB_TC_DNS_OFF;
}

INLINE bool private_destination(const struct sb_tc_assign_key *key) {
    if (key->family == AF_INET_VALUE) return sb_ebpf_ipv4_private_address(key->destination_addr);
    return sb_ebpf_ipv6_private_address(key->destination_addr);
}

INLINE bool force_intercept_destination(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key) {
    if (key->family == AF_INET_VALUE) {
        return sb_ebpf_force_intercept_ipv4(
            key->destination_addr,
            control->flags,
            SB_TC_FLAG_FORCE_INTERCEPT_IPV4,
            control->force_intercept_ipv4_prefix,
            control->force_intercept_ipv4_mask);
    }
    return sb_ebpf_force_intercept_ipv6(
        key->destination_addr,
        control->flags,
        SB_TC_FLAG_FORCE_INTERCEPT_IPV6,
        control->force_intercept_ipv6_prefix,
        control->force_intercept_ipv6_mask);
}

INLINE bool bypass_destination(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, bool shared) {
    if (flow->family == AF_INET_VALUE) {
        __u32 flag = shared ? SB_TC_FLAG_SHARED_BYPASS_IPV4 : SB_TC_FLAG_LOCAL_BYPASS_IPV4;
        if ((control->flags & flag) == 0U) return false;
        struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
        __builtin_memcpy(key.address, flow->destination_addr, 4U);
        return shared
            ? map_lookup(&tc_shared_bypass_ipv4, &key) != 0
            : map_lookup(&tc_local_bypass_ipv4, &key) != 0;
    }
    __u32 flag = shared ? SB_TC_FLAG_SHARED_BYPASS_IPV6 : SB_TC_FLAG_LOCAL_BYPASS_IPV6;
    if ((control->flags & flag) == 0U) return false;
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, flow->destination_addr, 16U);
    return shared
        ? map_lookup(&tc_shared_bypass_ipv6, &key) != 0
        : map_lookup(&tc_local_bypass_ipv6, &key) != 0;
}

INLINE bool source_address_excluded(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow) {
    if (flow->family == AF_INET_VALUE) {
        if ((control->flags & SB_TC_FLAG_EXCLUDE_SOURCE) == 0U) return false;
        struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
        __builtin_memcpy(key.address, flow->source_addr, 4U);
        return map_lookup(&tc_exclude_source_ipv4, &key) != 0;
    }
    if ((control->flags & SB_TC_FLAG_EXCLUDE_SOURCE) == 0U) return false;
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, flow->source_addr, 16U);
    return map_lookup(&tc_exclude_source_ipv6, &key) != 0;
}

INLINE bool source_address_included(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow) {
    if ((control->flags & SB_TC_FLAG_INCLUDE_SOURCE) == 0U) return false;
    if (flow->family == AF_INET_VALUE) {
        struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
        __builtin_memcpy(key.address, flow->source_addr, 4U);
        return map_lookup(&tc_include_source_ipv4, &key) != 0;
    }
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, flow->source_addr, 16U);
    return map_lookup(&tc_include_source_ipv6, &key) != 0;
}

INLINE bool host_destination(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow) {
    if (flow->family == AF_INET_VALUE) {
        if ((control->flags & SB_TC_FLAG_HOST_IPV4) == 0U) return false;
        struct sb_tc_ipv4_key key = {};
        __builtin_memcpy(key.address, flow->destination_addr, 4U);
        return map_lookup(&tc_host_ipv4, &key) != 0;
    }
    if ((control->flags & SB_TC_FLAG_HOST_IPV6) == 0U) return false;
    struct sb_tc_ipv6_key key = {};
    __builtin_memcpy(key.address, flow->destination_addr, 16U);
    return map_lookup(&tc_host_ipv6, &key) != 0;
}

INLINE bool source_mac_excluded(const struct sb_tc_control *control, const __u8 source_mac[6]) {
    if ((control->flags & SB_TC_FLAG_EXCLUDE_SOURCE_MAC) == 0U) return false;
    struct sb_tc_mac_key key = {};
    __builtin_memcpy(key.address, source_mac, 6U);
    return map_lookup(&tc_exclude_source_mac, &key) != 0;
}

INLINE bool source_mac_included(const struct sb_tc_control *control, const __u8 source_mac[6]) {
    if ((control->flags & SB_TC_FLAG_INCLUDE_SOURCE_MAC) == 0U) return false;
    struct sb_tc_mac_key key = {};
    __builtin_memcpy(key.address, source_mac, 6U);
    return map_lookup(&tc_include_source_mac, &key) != 0;
}

INLINE bool shared_source_selected(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, const __u8 source_mac[6]) {
    if (source_address_excluded(control, flow) || source_mac_excluded(control, source_mac)) return false;
    if ((control->flags & (SB_TC_FLAG_INCLUDE_SOURCE | SB_TC_FLAG_INCLUDE_SOURCE_MAC)) == 0U) return true;
    return source_address_included(control, flow) || source_mac_included(control, source_mac);
}

INLINE bool local_selected(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, __u32 socket_metadata_value) {
    if (force_intercept_destination(control, key)) return true;
    if (dns_bypassed(key->protocol, key->destination_port, control->local_dns_mode)) return false;
    if (dns_selected(key->protocol, key->destination_port, control->local_dns_mode)) return true;
    if ((socket_metadata_value & SB_EBPF_SOCKET_METADATA_POLICY_BYPASS) != 0U) return false;
    if ((socket_metadata_value & SB_EBPF_SOCKET_METADATA_POLICY_INTERCEPT) == 0U && uid_bypassed(skb, control)) return false;
    if (key->destination_port == 53U && control->local_dns_mode == SB_TC_DNS_RESPECT_POLICY) return true;
    if (port_bypassed(control, key, false)) return false;
    if (host_destination(control, key)) return false;
    if ((control->flags & SB_TC_FLAG_LOCAL_BYPASS_PRIVATE) != 0U && private_destination(key)) return false;
    return !bypass_destination(control, key, false);
}

// local_selected_cached 把判定结果记在 socket 本地存储里，用 policy_generation
// 做失效。一条被绕过的大流量连接原本每个包都要把整条链跑完才得出"绕过"，现在只有
// 第一个包付全额代价。
//
// 只对 TCP 缓存。未连接的 UDP socket 每个包的目的地址都可能不同，而判定是按目的
// 地算出来的，缓存下来就是错的；把目的地一起存进来再比对也不划算，那等于用一次
// 16 字节比较换掉一次哈希查找。
//
// 缓存的是最终判定，不是中间结果，所以 self-bypass 那条早退路径（在调用这里之前）
// 不受影响：sing-box 自己的 socket 根本走不到这儿。
INLINE bool local_selected_cached(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, __u32 socket_metadata_value) {
    // skb->sk 读一次、判一次空，然后只调一次 helper。
    //
    // 第一版分成"先只读查一次、没有再带 F_CREATE 查一次"两步，加载不了：
    // 编译器为第二次调用重新从 ctx 加载了 skb->sk，而 verifier 只认同一条路径上
    // 的判空，于是报 "R2 type=sock_common_or_null expected=sock_common"。带
    // F_CREATE 一次拿到指针，再按代号决定用还是重算，既绕开了这个问题，也比两次
    // 调用便宜。
    void *socket = skb->sk;
    if (key->protocol != IPPROTO_TCP_VALUE || socket == 0)
        return local_selected(skb, control, key, socket_metadata_value);
    // 新建的条目按这个零值初始化，generation 0 表示"还没有缓存过判定"。
    struct sb_tc_socket_verdict initial = {};
    struct sb_tc_socket_verdict *cached =
        sk_storage_get(&tc_local_verdict, socket, &initial, SB_TC_LOCAL_STORAGE_CREATE);
    if (cached == 0) return local_selected(skb, control, key, socket_metadata_value);
    // 代号必须在计算之前读。用户态先改策略 map、最后才写 control 推进代号
    // （internal/core/tc.go 的 UpdateUIDPolicy 等）；若在计算之后才读代号，
    // 一次跨过更新的计算会拿旧 map 得出的结果去标记新代号，而新代号之后不会再
    // 变，这条 socket 就永远停在旧判定上。先读，最坏情况是给结果标上旧代号，
    // 下一个包看到代号不同就重算。
    //
    // 计算之后再读一次：两次不同说明计算跨过了一次 control 写，结果可能混合了
    // 新旧状态，这种结果不缓存。这只能缩小、不能在弱内存序的 CPU 上从形式上消除
    // “读到撕裂的 control”的窗口——control 由 bpf 系统调用整块拷贝，没有锁。
    __u32 generation = *(volatile const __u32 *)&control->policy_generation;
    union sb_tc_socket_verdict_word current = {.word = *(volatile const __u64 *)cached};
    if (current.fields.generation != 0U && current.fields.generation == generation)
        return current.fields.verdict != 0U;
    bool selected = local_selected(skb, control, key, socket_metadata_value);
    if (*(volatile const __u32 *)&control->policy_generation != generation) return selected;
    union sb_tc_socket_verdict_word next = {
        .fields = {.generation = generation, .verdict = selected ? 1U : 0U},
    };
    *(volatile __u64 *)cached = next.word;
    return selected;
}

INLINE bool shared_selected(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, const __u8 source_mac[6]) {
    if (force_intercept_destination(control, key)) return true;
    if (dns_bypassed(key->protocol, key->destination_port, control->shared_dns_mode)) return false;
    if (dns_selected(key->protocol, key->destination_port, control->shared_dns_mode)) return true;
    if (!shared_source_selected(control, key, source_mac)) return false;
    if (key->destination_port == 53U && control->shared_dns_mode == SB_TC_DNS_RESPECT_POLICY) return true;
    if (port_bypassed(control, key, true)) return false;
    if (host_destination(control, key)) return false;
    if ((control->flags & SB_TC_FLAG_SHARED_BYPASS_PRIVATE) != 0U && private_destination(key)) return false;
    return !bypass_destination(control, key, true);
}

INLINE bool parse_ethernet(void *data, void *data_end, __u16 *protocol, __u32 *l3_offset, __u8 source_mac[6]) {
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return false;
    *protocol = network_order16(ethernet->protocol);
    *l3_offset = sizeof(*ethernet);
    __builtin_memcpy(source_mac, ethernet->source, 6U);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (*protocol != ETH_P_8021Q_VALUE && *protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + *l3_offset;
        if ((void *)(vlan + 1) > data_end) return false;
        *protocol = network_order16(vlan->protocol);
        *l3_offset += sizeof(*vlan);
    }
    return true;
}

INLINE bool fill_ipv4_key(void *data, void *data_end, __u32 l3_offset,
    const struct sb_tc_control *control, struct sb_tc_assign_key *key, __u32 fragment_stat) {
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U ||
        !protocol_enabled(control, ip->protocol)) return false;
    if ((network_order16(ip->fragment_offset) & (IPV4_FRAGMENT_OFFSET_MASK | IPV4_FRAGMENT_MORE)) != 0U) {
        increment_stat(fragment_stat);
        return false;
    }
    __u32 header_length = (__u32)ip->ihl * 4U;
    struct transport_ports *ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end) return false;
    __u16 source_port = network_order16(ports->source);
    __u16 destination_port = network_order16(ports->destination);
    if (service_port(ip->protocol, source_port, destination_port)) return false;
    __u8 destination[4];
    __builtin_memcpy(destination, &ip->destination, 4U);
    if (sb_ebpf_ipv4_safety_bypass(destination)) return false;
    __builtin_memset(key, 0, sizeof(*key));
    key->family = AF_INET_VALUE;
    key->protocol = ip->protocol;
    key->source_port = source_port;
    key->destination_port = destination_port;
    __builtin_memcpy(key->source_addr, &ip->source, 4U);
    __builtin_memcpy(key->destination_addr, &ip->destination, 4U);
    return true;
}

INLINE bool fill_ipv6_key(void *data, void *data_end, __u32 l3_offset,
    const struct sb_tc_control *control, struct sb_tc_assign_key *key, __u32 fragment_stat) {
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (network_order32(ip->version_flow) >> 28U) != 6U) return false;
    __u8 protocol = ip->next_header;
    __u32 transport_offset = l3_offset + sizeof(*ip);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 4U; ++depth) {
        if (protocol == IPPROTO_FRAGMENT_VALUE) {
            struct ipv6_fragment_header *fragment = data + transport_offset;
            if ((void *)(fragment + 1) > data_end) return false;
            if ((network_order16(fragment->offset_flags) &
                    (IPV6_FRAGMENT_OFFSET_MASK | IPV6_FRAGMENT_MORE)) != 0U) {
                increment_stat(fragment_stat);
                return false;
            }
            protocol = fragment->next_header;
            transport_offset += sizeof(*fragment);
            continue;
        }
        if (protocol != IPPROTO_HOPOPTS_VALUE && protocol != IPPROTO_ROUTING_VALUE &&
            protocol != IPPROTO_DSTOPTS_VALUE && protocol != IPPROTO_AH_VALUE) break;
        struct ipv6_extension_header *extension = data + transport_offset;
        if ((void *)(extension + 1) > data_end) return false;
        __u32 extension_length = protocol == IPPROTO_AH_VALUE
            ? ((__u32)extension->length + 2U) * 4U
            : ((__u32)extension->length + 1U) * 8U;
        if (extension_length < 8U || data + transport_offset + extension_length > data_end) return false;
        protocol = extension->next_header;
        transport_offset += extension_length;
    }
    if (!protocol_enabled(control, protocol)) return false;
    struct transport_ports *ports = data + transport_offset;
    if ((void *)(ports + 1) > data_end) return false;
    __u16 source_port = network_order16(ports->source);
    __u16 destination_port = network_order16(ports->destination);
    if (service_port(protocol, source_port, destination_port) ||
        sb_ebpf_ipv6_safety_bypass(ip->destination)) return false;
    __builtin_memset(key, 0, sizeof(*key));
    key->family = AF_INET6_VALUE;
    key->protocol = protocol;
    key->source_port = source_port;
    key->destination_port = destination_port;
    copy_address(key->source_addr, ip->source, 16U);
    copy_address(key->destination_addr, ip->destination, 16U);
    return true;
}

INLINE bool parse_flow(struct __sk_buff *skb, const struct sb_tc_control *control,
    __u32 ipv6_flag, bool ethernet, struct sb_tc_assign_key *key, __u8 source_mac[6], __u32 fragment_stat) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u16 ether_type;
    __u32 l3_offset;
    if (ethernet) {
        if (!parse_ethernet(data, data_end, &ether_type, &l3_offset, source_mac)) return false;
    } else {
        ether_type = network_order16(skb->protocol);
        l3_offset = 0U;
        __builtin_memset(source_mac, 0, 6U);
    }
    if (ether_type == ETH_P_IP_VALUE && (control->flags & SB_TC_FLAG_IPV4) != 0U) {
        return fill_ipv4_key(data, data_end, l3_offset, control, key, fragment_stat);
    }
    if (ether_type == ETH_P_IPV6_VALUE && (control->flags & ipv6_flag) != 0U) {
        return fill_ipv6_key(data, data_end, l3_offset, control, key, fragment_stat);
    }
    return false;
}

NOINLINE struct bpf_sock *lookup_tcp_socket(struct __sk_buff *skb,
    const struct sb_tc_assign_key *key) {
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (key->family == AF_INET_VALUE) {
        __builtin_memcpy(&tuple.ipv4.saddr, key->source_addr, 4U);
        __builtin_memcpy(&tuple.ipv4.daddr, key->destination_addr, 4U);
        tuple.ipv4.sport = network_order16(key->source_port);
        tuple.ipv4.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        copy_address((__u8 *)&tuple.ipv6.saddr, key->source_addr, 16U);
        copy_address((__u8 *)&tuple.ipv6.daddr, key->destination_addr, 16U);
        tuple.ipv6.sport = network_order16(key->source_port);
        tuple.ipv6.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv6);
    }
    struct bpf_sock *socket = skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
    if (socket != 0 && socket->state != BPF_TCP_LISTEN) return socket;
    if (socket != 0) sk_release(socket);
    __u32 listener = key->family == AF_INET_VALUE ? SB_TC_LISTENER_TCP4 : SB_TC_LISTENER_TCP6;
    return map_lookup(&tc_listener_sockets, &listener);
}

NOINLINE struct bpf_sock *lookup_tcp_socket_legacy(struct __sk_buff *skb,
    const struct sb_tc_control *control, const struct sb_tc_assign_key *key) {
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (key->family == AF_INET_VALUE) {
        __builtin_memcpy(&tuple.ipv4.saddr, key->source_addr, 4U);
        __builtin_memcpy(&tuple.ipv4.daddr, key->destination_addr, 4U);
        tuple.ipv4.sport = network_order16(key->source_port);
        tuple.ipv4.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        copy_address((__u8 *)&tuple.ipv6.saddr, key->source_addr, 16U);
        copy_address((__u8 *)&tuple.ipv6.daddr, key->destination_addr, 16U);
        tuple.ipv6.sport = network_order16(key->source_port);
        tuple.ipv6.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv6);
    }
    struct bpf_sock *socket = skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
    if (socket != 0 && socket->state != BPF_TCP_LISTEN) return socket;
    if (socket != 0) sk_release(socket);

    // The legacy path has no SOCKMAP. Query the actual transparent listener
    // port after the established-socket lookup so wildcard listeners remain
    // usable on kernels that reject SOCKMAP or map-backed sk_assign.
    if (key->family == AF_INET_VALUE) {
        tuple.ipv4.dport = network_order16(control->listener_port);
    } else {
        tuple.ipv6.dport = network_order16(control->listener_port);
    }
    return skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
}

NOINLINE struct bpf_sock *lookup_udp_socket(struct __sk_buff *skb,
    const struct sb_tc_control *control, const struct sb_tc_assign_key *key) {
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (key->family == AF_INET_VALUE) {
        __builtin_memcpy(&tuple.ipv4.saddr, key->source_addr, 4U);
        __builtin_memcpy(&tuple.ipv4.daddr, key->destination_addr, 4U);
        tuple.ipv4.sport = network_order16(key->source_port);
        tuple.ipv4.dport = network_order16(control->listener_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        copy_address((__u8 *)&tuple.ipv6.saddr, key->source_addr, 16U);
        copy_address((__u8 *)&tuple.ipv6.daddr, key->destination_addr, 16U);
        tuple.ipv6.sport = network_order16(key->source_port);
        tuple.ipv6.dport = network_order16(control->listener_port);
        tuple_size = sizeof(tuple.ipv6);
    }
    return sk_lookup_udp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
}

INLINE bool source_mac_equal(const __u8 left[6], const __u8 right[6]) {
    __u32 left_low, right_low;
    __u16 left_high, right_high;
    __builtin_memcpy(&left_low, left, 4U);
    __builtin_memcpy(&right_low, right, 4U);
    __builtin_memcpy(&left_high, left + 4U, 2U);
    __builtin_memcpy(&right_high, right + 4U, 2U);
    return left_low == right_low && left_high == right_high;
}

// Avoid memcmp: Clang may emit an unresolved libc call for the 64-byte ABI.
// Fold scalar differences into one word so comparison stays native BPF; the
// fixed-width memcpy loads also avoid alignment/aliasing assumptions on comm.
INLINE bool socket_creator_equal(const struct sb_socket_creator *left, const struct sb_socket_creator *right) {
    __u64 left_comm_low, right_comm_low, left_comm_high, right_comm_high;
    __builtin_memcpy(&left_comm_low, left->comm, 8U);
    __builtin_memcpy(&right_comm_low, right->comm, 8U);
    __builtin_memcpy(&left_comm_high, left->comm + 8U, 8U);
    __builtin_memcpy(&right_comm_high, right->comm + 8U, 8U);
    __u64 different = left->cookie ^ right->cookie;
    different |= left->start_time_ns ^ right->start_time_ns;
    different |= left->process_id ^ right->process_id;
    different |= left->thread_id ^ right->thread_id;
    different |= left->user_id ^ right->user_id;
    different |= left->flags ^ right->flags;
    different |= left_comm_low ^ right_comm_low;
    different |= left_comm_high ^ right_comm_high;
    different |= left->process_name_hash ^ right->process_name_hash;
    different |= left->exe_inode ^ right->exe_inode;
    return different == 0U;
}
// build_assignment 填好 assign_socket 系列要写的值，并报告它与现有条目是否不同。
//
// delivery 路径的包是本机出站包被重定向回来的同一条流，本机路径（record_local_socket）
// 已经在同一个键下写了 cookie 和 socket 身份，这里原样带过去，否则 delivery 的第一次
// 写就会把它们抹掉。shared 路径的包来自别的主机，没有本机 socket：cookie 与身份都是 0，
// 若同键下残留着本机条目，就把它改写成 0，而不是继续挂着一个不属于这条流的身份。
INLINE bool build_assignment(struct sb_tc_assign_value *value, const struct sb_tc_assign_value *existing,
    __u32 ifindex, const __u8 source_mac[6], __u8 path, bool source_mac_valid, __u32 epoch) {
    __builtin_memset(value, 0, sizeof(*value));
    value->activity_epoch = epoch;
    value->ifindex = ifindex;
    value->path = path;
    value->source_mac_valid = source_mac_valid;
    __builtin_memcpy(value->source_mac, source_mac, 6U);
    if (path == SB_TC_PATH_DELIVERY && existing != 0) {
        value->socket_cookie = existing->socket_cookie;
        value->socket_uid = existing->socket_uid;
        value->socket_cgroup_id = existing->socket_cgroup_id;
        value->identity_flags = existing->identity_flags;
        value->creator = existing->creator;
        value->charge_uid = existing->charge_uid;
        value->charge_tag = existing->charge_tag;
    }
    if (existing == 0) return true;
    if (existing->socket_cookie != value->socket_cookie || existing->ifindex != value->ifindex ||
        existing->path != value->path || existing->source_mac_valid != value->source_mac_valid ||
        existing->socket_uid != value->socket_uid || existing->socket_cgroup_id != value->socket_cgroup_id ||
        existing->identity_flags != value->identity_flags ||
        existing->charge_uid != value->charge_uid || existing->charge_tag != value->charge_tag ||
        !socket_creator_equal(&existing->creator, &value->creator)) return true;
    return source_mac_valid && !source_mac_equal(existing->source_mac, value->source_mac);
}

// touch_assignment stamps the current activity period into an unchanged
// entry. The store happens once per entry per period; every other packet only
// reads the field. A racing writer on another CPU can at worst leave an older
// period, which makes the entry look idle sooner; the sweep rechecks the
// whole value before deleting and the next packet recreates a deleted entry.
INLINE void touch_assignment(struct sb_tc_assign_value *existing, __u32 epoch) {
    if (existing->activity_epoch != epoch) existing->activity_epoch = epoch;
}

NOINLINE int assign_socket(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, const __u8 source_mac[6], __u8 path) {
    bool source_mac_valid = (path & SB_TC_PATH_SOURCE_MAC_VALID) != 0U;
    path &= ~SB_TC_PATH_SOURCE_MAC_VALID;
    struct bpf_sock *socket = key->protocol == IPPROTO_TCP_VALUE
        ? lookup_tcp_socket(skb, key)
        : lookup_udp_socket(skb, control, key);
    if (socket == 0) {
        increment_stat(SB_TC_STAT_SOCKET_LOOKUP_FAILURE);
        return TC_ACT_SHOT;
    }
    struct sb_tc_assign_key assignment_key = *key;
    if (key->protocol == IPPROTO_UDP_VALUE && path == SB_TC_PATH_SHARED)
        assignment_key.interface_index = skb->ifindex;
    struct sb_tc_assign_value *existing = map_lookup(&tc_assignment, &assignment_key);
    struct sb_tc_assign_value value;
    __u32 epoch = *(volatile const __u32 *)&control->activity_epoch;
    bool assignment_changed = build_assignment(&value, existing, skb->ifindex, source_mac, path, source_mac_valid, epoch);
    long result = sk_assign(skb, socket, 0U);
    sk_release(socket);
    if (result != 0) {
        increment_stat(SB_TC_STAT_SK_ASSIGN_FAILURE);
        return TC_ACT_SHOT;
    }
    if (assignment_changed) {
        if (map_update(&tc_assignment, &assignment_key, &value, BPF_ANY) != 0) {
            increment_stat(SB_TC_STAT_ASSIGNMENT_UPDATE_FAILURE);
            return TC_ACT_SHOT;
        }
        bump_assignment_generation();
    } else {
        touch_assignment(existing, epoch);
    }
    return TC_ACT_OK;
}

NOINLINE int assign_socket_legacy(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, const __u8 source_mac[6], __u8 path) {
    bool source_mac_valid = (path & SB_TC_PATH_SOURCE_MAC_VALID) != 0U;
    path &= ~SB_TC_PATH_SOURCE_MAC_VALID;
    struct bpf_sock *socket = key->protocol == IPPROTO_TCP_VALUE
        ? lookup_tcp_socket_legacy(skb, control, key)
        : lookup_udp_socket(skb, control, key);
    if (socket == 0) {
        increment_stat(SB_TC_STAT_SOCKET_LOOKUP_FAILURE);
        return TC_ACT_SHOT;
    }
    struct sb_tc_assign_key assignment_key = *key;
    if (key->protocol == IPPROTO_UDP_VALUE && path == SB_TC_PATH_SHARED)
        assignment_key.interface_index = skb->ifindex;
    struct sb_tc_assign_value *existing = map_lookup(&tc_assignment, &assignment_key);
    struct sb_tc_assign_value value;
    __u32 epoch = *(volatile const __u32 *)&control->activity_epoch;
    bool assignment_changed = build_assignment(&value, existing, skb->ifindex, source_mac, path, source_mac_valid, epoch);
    long result = sk_assign(skb, socket, 0U);
    sk_release(socket);
    if (result != 0) {
        increment_stat(SB_TC_STAT_SK_ASSIGN_FAILURE);
        return TC_ACT_SHOT;
    }
    if (assignment_changed) {
        if (map_update(&tc_assignment, &assignment_key, &value, BPF_ANY) != 0) {
            increment_stat(SB_TC_STAT_ASSIGNMENT_UPDATE_FAILURE);
            return TC_ACT_SHOT;
        }
        bump_assignment_generation();
    } else {
        touch_assignment(existing, epoch);
    }
    return TC_ACT_OK;
}

NOINLINE int assign_udp_socket(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, const __u8 source_mac[6], __u8 path) {
    bool source_mac_valid = (path & SB_TC_PATH_SOURCE_MAC_VALID) != 0U;
    path &= ~SB_TC_PATH_SOURCE_MAC_VALID;
    struct bpf_sock *socket = lookup_udp_socket(skb, control, key);
    if (socket == 0) {
        increment_stat(SB_TC_STAT_SOCKET_LOOKUP_FAILURE);
        return TC_ACT_SHOT;
    }
    struct sb_tc_assign_key assignment_key = *key;
    assignment_key.interface_index = path == SB_TC_PATH_SHARED ? skb->ifindex : 0U;
    struct sb_tc_assign_value *existing = map_lookup(&tc_assignment, &assignment_key);
    struct sb_tc_assign_value value;
    __u32 epoch = *(volatile const __u32 *)&control->activity_epoch;
    bool assignment_changed = build_assignment(&value, existing, skb->ifindex, source_mac, path, source_mac_valid, epoch);
    long result = sk_assign(skb, socket, 0U);
    sk_release(socket);
    if (result != 0) {
        increment_stat(SB_TC_STAT_SK_ASSIGN_FAILURE);
        return TC_ACT_SHOT;
    }
    if (assignment_changed) {
        if (map_update(&tc_assignment, &assignment_key, &value, BPF_ANY) != 0) {
            increment_stat(SB_TC_STAT_ASSIGNMENT_UPDATE_FAILURE);
            return TC_ACT_SHOT;
        }
        bump_assignment_generation();
    } else {
        touch_assignment(existing, epoch);
    }
    return TC_ACT_OK;
}

// record_local_socket 把本机出站 socket 的 cookie 和身份（UID、cgroup id）记进
// tc_assignment，供用户态在连接到达监听端时按流查回。只有身份采集变体
// （*_process 段）调用它，轻量变体（*_mark 段）一个 helper 都不多调。
//
// 稳态每个被选中的包：一次 cookie helper、一次哈希查找、一次 uid helper。
// cookie 相同不能直接早退：socket 的 cgroup 在创建时就定下（cgroup_sk_alloc），
// 同一 cookie 下不会变，但 sk_uid 可以被 fchown 改掉（net/socket.c 的
// sockfs_setattr），所以每个包还要比一次 uid。cookie 不同（新 socket 复用了同一
// 五元组，UDP 常见）则整条重写，旧条目的 delivery 字段一并丢弃，由 delivery
// 路径下一个包重新填。
//
// cgroup id 为 0 表示这一刻 skb 上没有 full socket（例如 TIME_WAIT 发出的包，
// 它沿用原 socket 的 cookie）。这种包不降级已有的有效身份。
INLINE void record_local_socket(struct __sk_buff *skb, const struct sb_tc_assign_key *key) {
    __u64 socket_cookie = get_socket_cookie(skb);
    if (socket_cookie == 0U) return;
    struct sb_tc_assign_value *existing = map_lookup(&tc_assignment, key);
    struct sb_tc_assign_value value = {};
    if (existing != 0 && existing->socket_cookie == socket_cookie) {
        __u32 socket_uid = 0U;
        if ((existing->identity_flags & SB_TC_IDENTITY_VALID) == SB_TC_IDENTITY_VALID) {
            socket_uid = get_socket_uid(skb);
            if (socket_uid == existing->socket_uid) return;
        }
        __u64 cgroup_id = skb_cgroup_id(skb);
        if (cgroup_id == 0U) return;
        if ((existing->identity_flags & SB_TC_IDENTITY_VALID) != SB_TC_IDENTITY_VALID)
            socket_uid = get_socket_uid(skb);
        value = *existing;
        value.socket_uid = socket_uid;
        value.socket_cgroup_id = cgroup_id;
        value.identity_flags = SB_TC_IDENTITY_VALID;
    } else {
        value.socket_cookie = socket_cookie;
        __u64 cgroup_id = skb_cgroup_id(skb);
        if (cgroup_id != 0U) {
            value.socket_uid = get_socket_uid(skb);
            value.socket_cgroup_id = cgroup_id;
            value.identity_flags = SB_TC_IDENTITY_VALID;
        }
    }
    map_update(&tc_assignment, key, &value, BPF_ANY);
    bump_assignment_generation();
}

// Only the opt-in creator variants reach this function. Existing valid
// snapshots are immutable: the steady path does not read SK_STORAGE again.
// A missing entry on a full socket is cached for that cookie: the creation
// hook has already run, so old sockets cannot gain a creation record later.
// Non-full sockets and invalid non-null entries are retried. fchown refreshes
// billing UID independently; a new cookie always starts from zero.
//
// netd's cookie tag is looked up once per cookie on the first packet that
// carries a full socket, and a miss is cached like a missing creator. Apps and
// services tag before connecting (TrafficStats.tagSocket), so the SYN already
// sees the tag; a retag later in the socket's life is deliberately not
// followed because the steady path must stay free of extra lookups.
INLINE void record_local_socket_creator(struct __sk_buff *skb, const struct sb_tc_assign_key *key) {
    __u64 cookie = get_socket_cookie(skb);
    if (cookie == 0U) return;
    struct sb_tc_assign_value *existing = map_lookup(&tc_assignment, key);
    struct sb_tc_assign_value value = {};
    bool same_socket = existing != 0 && existing->socket_cookie == cookie;
    bool changed = !same_socket;
    if (same_socket) value = *existing;
    else value.socket_cookie = cookie;

    __u32 uid = get_socket_uid(skb);
    bool read_identity = !same_socket || (value.identity_flags & SB_TC_IDENTITY_VALID) != SB_TC_IDENTITY_VALID ||
        value.socket_uid != uid;
    bool read_creator = !socket_creator_valid(&value.creator, cookie) &&
        (value.identity_flags & SB_TC_IDENTITY_CREATOR_CHECKED) == 0U;
    bool read_charge = (value.identity_flags & SB_TC_IDENTITY_CHARGE_CHECKED) == 0U;
    __u64 cgroup_id = 0U;
    if (read_identity || read_creator || read_charge) {
        // Only this packet's helper result proves it currently carries a full
        // socket. A saved cgroup ID cannot prove that for TIME_WAIT packets.
        cgroup_id = skb_cgroup_id(skb);
        if (read_identity && cgroup_id != 0U) {
            value.socket_uid = uid;
            value.socket_cgroup_id = cgroup_id;
            value.identity_flags |= SB_TC_IDENTITY_VALID;
            changed = true;
        }
    }
    if (read_creator && skb->sk != 0) {
        const struct sb_socket_creator *creator = sk_storage_get(&socket_creators, skb->sk, 0, 0U);
        if (creator != 0 && socket_creator_valid(creator, cookie)) {
            value.creator = *creator;
            value.identity_flags |= SB_TC_IDENTITY_CREATOR_CHECKED;
            changed = true;
        } else if (creator == 0 && cgroup_id != 0U) {
            value.identity_flags |= SB_TC_IDENTITY_CREATOR_CHECKED;
            changed = true;
        }
    }
    if (read_charge && cgroup_id != 0U) {
        const struct sb_netd_uid_tag *charge = map_lookup(&netd_cookie_tags, &cookie);
        value.identity_flags |= SB_TC_IDENTITY_CHARGE_CHECKED;
        if (charge != 0) {
            value.charge_uid = charge->uid;
            value.charge_tag = charge->tag;
            value.identity_flags |= SB_TC_IDENTITY_CHARGE_VALID;
        }
        changed = true;
    }
    if (changed) {
        map_update(&tc_assignment, key, &value, BPF_ANY);
        bump_assignment_generation();
    }
}

INLINE int redirect_local(struct __sk_buff *skb, const struct sb_tc_control *control, bool ethernet) {
    if (ethernet) {
        if (skb_store_bytes(skb, 0U, control->delivery_mac, 6U, 0U) != 0) return TC_ACT_UNSPEC;
    } else {
        __be16 protocol = skb->protocol;
        if (skb_change_head(skb, sizeof(struct ethernet_header), 0U) != 0) return TC_ACT_UNSPEC;
        struct ethernet_header header = {.protocol = protocol};
        __builtin_memcpy(header.destination, control->delivery_mac, 6U);
        if (skb_store_bytes(skb, 0U, &header, sizeof(header), 0U) != 0) return TC_ACT_SHOT;
    }
    return redirect((int)control->delivery_ifindex, 0U);
}

INLINE int local_egress_mark(struct __sk_buff *skb, bool ethernet, bool track_process, bool track_creator) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U || control->delivery_ifindex == 0U) return TC_ACT_UNSPEC;
    if (skb->ingress_ifindex != 0U) return TC_ACT_UNSPEC;
    __u32 socket_metadata_value = socket_metadata(skb);
    if ((socket_metadata_value & SB_EBPF_SOCKET_METADATA_SELF_BYPASS) != 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_LOCAL_IPV6, ethernet, &key, source_mac,
            SB_TC_STAT_LOCAL_FRAGMENT_PASS)) return TC_ACT_UNSPEC;
    if (!local_selected_cached(skb, control, &key, socket_metadata_value)) return TC_ACT_UNSPEC;
    // 只记被选中的流：没被选中的包不会到达 sing-box，没人来查它的条目。
    if (track_creator) record_local_socket_creator(skb, &key);
    else if (track_process) record_local_socket(skb, &key);
    return redirect_local(skb, control, ethernet);
}

SEC("classifier/local_egress_ethernet_mark")
int sing_ebpf_tc_local_egress_ethernet_mark(struct __sk_buff *skb) {
	return local_egress_mark(skb, true, false, false);
}

SEC("classifier/local_egress_raw_ip_mark")
int sing_ebpf_tc_local_egress_raw_ip_mark(struct __sk_buff *skb) {
	return local_egress_mark(skb, false, false, false);
}

SEC("classifier/local_egress_ethernet_process")
int sing_ebpf_tc_local_egress_ethernet_process(struct __sk_buff *skb) {
	return local_egress_mark(skb, true, true, false);
}

SEC("classifier/local_egress_raw_ip_process")
int sing_ebpf_tc_local_egress_raw_ip_process(struct __sk_buff *skb) {
	return local_egress_mark(skb, false, true, false);
}

SEC("classifier/local_egress_ethernet_creator")
int sing_ebpf_tc_local_egress_ethernet_creator(struct __sk_buff *skb) {
    return local_egress_mark(skb, true, true, true);
}

SEC("classifier/local_egress_raw_ip_creator")
int sing_ebpf_tc_local_egress_raw_ip_creator(struct __sk_buff *skb) {
    return local_egress_mark(skb, false, true, true);
}

INLINE int shared_ingress(struct __sk_buff *skb, bool ethernet) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, &key, source_mac,
            SB_TC_STAT_SHARED_FRAGMENT_PASS)) return TC_ACT_UNSPEC;
    if (!ethernet &&
        (control->flags & (SB_TC_FLAG_INCLUDE_SOURCE_MAC | SB_TC_FLAG_EXCLUDE_SOURCE_MAC)) != 0U) {
        return TC_ACT_UNSPEC;
    }
    if (!shared_selected(control, &key, source_mac)) return TC_ACT_UNSPEC;
    skb->mark |= control->routing_mark;
    __u8 path = SB_TC_PATH_SHARED;
    if (ethernet) path |= SB_TC_PATH_SOURCE_MAC_VALID;
    return assign_socket(skb, control, &key, source_mac, path);
}

SEC("classifier/shared_ingress_ethernet")
int sing_ebpf_tc_shared_ingress_ethernet(struct __sk_buff *skb) {
    return shared_ingress(skb, true);
}

SEC("classifier/shared_ingress_raw_ip")
int sing_ebpf_tc_shared_ingress_raw_ip(struct __sk_buff *skb) {
    return shared_ingress(skb, false);
}

INLINE int shared_ingress_legacy(struct __sk_buff *skb, bool ethernet) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, &key, source_mac,
            SB_TC_STAT_SHARED_FRAGMENT_PASS)) return TC_ACT_UNSPEC;
    if (!ethernet &&
        (control->flags & (SB_TC_FLAG_INCLUDE_SOURCE_MAC | SB_TC_FLAG_EXCLUDE_SOURCE_MAC)) != 0U) {
        return TC_ACT_UNSPEC;
    }
    if (!shared_selected(control, &key, source_mac)) return TC_ACT_UNSPEC;
    skb->mark |= control->routing_mark;
    __u8 path = SB_TC_PATH_SHARED;
    if (ethernet) path |= SB_TC_PATH_SOURCE_MAC_VALID;
    return assign_socket_legacy(skb, control, &key, source_mac, path);
}

SEC("classifier/shared_ingress_ethernet_legacy")
int sing_ebpf_tc_shared_ingress_ethernet_legacy(struct __sk_buff *skb) {
    return shared_ingress_legacy(skb, true);
}

SEC("classifier/shared_ingress_raw_ip_legacy")
int sing_ebpf_tc_shared_ingress_raw_ip_legacy(struct __sk_buff *skb) {
    return shared_ingress_legacy(skb, false);
}

INLINE int shared_ingress_udp(struct __sk_buff *skb, bool ethernet) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, &key, source_mac,
            SB_TC_STAT_SHARED_FRAGMENT_PASS)) return TC_ACT_UNSPEC;
    if (!ethernet &&
        (control->flags & (SB_TC_FLAG_INCLUDE_SOURCE_MAC | SB_TC_FLAG_EXCLUDE_SOURCE_MAC)) != 0U) {
        return TC_ACT_UNSPEC;
    }
    if (!shared_selected(control, &key, source_mac)) return TC_ACT_UNSPEC;
    skb->mark |= control->routing_mark;
    __u8 path = SB_TC_PATH_SHARED;
    if (ethernet) path |= SB_TC_PATH_SOURCE_MAC_VALID;
    return assign_udp_socket(skb, control, &key, source_mac, path);
}

SEC("classifier/shared_ingress_ethernet_udp")
int sing_ebpf_tc_shared_ingress_ethernet_udp(struct __sk_buff *skb) {
    return shared_ingress_udp(skb, true);
}

SEC("classifier/shared_ingress_raw_ip_udp")
int sing_ebpf_tc_shared_ingress_raw_ip_udp(struct __sk_buff *skb) {
    return shared_ingress_udp(skb, false);
}

SEC("classifier/delivery_ingress")
int sing_ebpf_tc_delivery_ingress(struct __sk_buff *skb) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_LOCAL_IPV6, true, &key, source_mac,
            SB_TC_STAT_COUNT)) return TC_ACT_UNSPEC;
    skb->mark |= control->routing_mark;
    return assign_socket(skb, control, &key, source_mac, SB_TC_PATH_DELIVERY);
}

SEC("classifier/delivery_ingress_legacy")
int sing_ebpf_tc_delivery_ingress_legacy(struct __sk_buff *skb) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_LOCAL_IPV6, true, &key, source_mac,
            SB_TC_STAT_COUNT)) return TC_ACT_UNSPEC;
    skb->mark |= control->routing_mark;
    return assign_socket_legacy(skb, control, &key, source_mac, SB_TC_PATH_DELIVERY);
}

SEC("classifier/delivery_ingress_udp")
int sing_ebpf_tc_delivery_ingress_udp(struct __sk_buff *skb) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_LOCAL_IPV6, true, &key, source_mac,
            SB_TC_STAT_COUNT)) return TC_ACT_UNSPEC;
    skb->mark |= control->routing_mark;
    return assign_udp_socket(skb, control, &key, source_mac, SB_TC_PATH_DELIVERY);
}

char _license[] SEC("license") = "GPL";
