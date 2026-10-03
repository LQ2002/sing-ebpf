// Host-side unit test of the production C helpers, with kernel helpers mocked.
// This verifies state transitions, not kernel verifier or real packet behavior.
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../../native/tc.bpf.c"

static struct sb_tc_assign_value saved;
static struct sb_socket_creator storage;
static bool saved_present, storage_present;
static __u64 fake_cookie, fake_cgroup;
static __u32 fake_uid;
static int storage_reads, updates;

static void *lookup(void *map, const void *key) {
    assert(map == &tc_assignment);
    return saved_present ? &saved : NULL;
}
static long update(void *map, const void *key, const void *value, __u64 flags) {
    assert(map == &tc_assignment && flags == BPF_ANY);
    saved = *(const struct sb_tc_assign_value *)value;
    saved_present = true;
    ++updates;
    return 0;
}
static void *read_storage(void *map, void *socket, void *value, __u64 flags) {
    assert(map == &socket_creators && socket != NULL && value == NULL && flags == 0);
    ++storage_reads;
    return storage_present ? &storage : NULL;
}
static __u64 cookie(void *ctx) { return fake_cookie; }
static __u64 cgroup(void *ctx) { return fake_cgroup; }
static __u32 uid(void *ctx) { return fake_uid; }
static void reset(void) {
    memset(&saved, 0, sizeof(saved));
    saved_present = false;
    storage_present = true;
    fake_cookie = 101;
    fake_cgroup = 202;
    fake_uid = 303;
    storage = (struct sb_socket_creator){.cookie = fake_cookie, .start_time_ns = 999,
        .process_id = 44, .thread_id = 45, .user_id = 0, .flags = SB_SOCKET_CREATOR_VALID,
        .comm = "creator-test"};
    storage_reads = updates = 0;
}

int main(void) {
    map_lookup = lookup;
    map_update = update;
    get_socket_cookie = cookie;
    get_socket_uid = uid;
    skb_cgroup_id = cgroup;
    sk_storage_get = read_storage;
    // Every ABI byte, including the tail of comm, participates in equality.
    struct sb_socket_creator sample = {.cookie = 7, .start_time_ns = 8,
        .process_id = 9, .thread_id = 10, .user_id = 11, .flags = 1, .comm = "compare-all"};
    assert(socket_creator_equal(&sample, &sample));
    for (unsigned int index = 0; index < sizeof(sample); ++index) {
        struct sb_socket_creator different = sample;
        ((__u8 *)&different)[index] ^= 0x5a;
        assert(!socket_creator_equal(&sample, &different));
    }
    struct bpf_sock socket = {};
    struct __sk_buff skb = {.sk = &socket};
    struct sb_tc_assign_key key = {};
    const __u8 mac[6] = {1, 2, 3, 4, 5, 6};
    struct sb_tc_assign_value value;

    reset();
    record_local_socket_creator(&skb, &key);
    assert(saved.socket_cookie == fake_cookie && saved.socket_uid == fake_uid);
    assert(saved.socket_cgroup_id == fake_cgroup && saved.identity_flags == (SB_TC_IDENTITY_VALID | SB_TC_IDENTITY_CREATOR_CHECKED));
    assert(memcmp(&saved.creator, &storage, sizeof(storage)) == 0);
    struct sb_socket_creator original = saved.creator;
    assert(storage_reads == 1 && updates == 1);
    storage.process_id = 900;
    record_local_socket_creator(&skb, &key);
    assert(storage_reads == 1 && updates == 1);
    assert(memcmp(&saved.creator, &original, sizeof(original)) == 0);
    fake_uid++;
    record_local_socket_creator(&skb, &key);
    assert(saved.socket_uid == fake_uid && storage_reads == 1 && updates == 2);
    assert(memcmp(&saved.creator, &original, sizeof(original)) == 0);
    fake_cgroup = 0;
    fake_uid = 65534;
    skb.sk = NULL;
    record_local_socket_creator(&skb, &key);
    assert(saved.socket_uid == 304 && saved.socket_cgroup_id == 202);
    assert(storage_reads == 1 && updates == 2);
    assert(memcmp(&saved.creator, &original, sizeof(original)) == 0);
    skb.sk = &socket;

    // A full socket with no producer entry is cached as missing for its cookie.
    reset();
    storage_present = false;
    record_local_socket_creator(&skb, &key);
    assert(saved.creator.flags == 0 && updates == 1 && storage_reads == 1);
    assert(saved.identity_flags & SB_TC_IDENTITY_CREATOR_CHECKED);
    record_local_socket_creator(&skb, &key);
    assert(updates == 1 && storage_reads == 1);
    storage_present = true;
    record_local_socket_creator(&skb, &key);
    assert(saved.creator.flags == 0 && updates == 1 && storage_reads == 1);
    fake_uid++;
    record_local_socket_creator(&skb, &key);
    assert(saved.identity_flags & SB_TC_IDENTITY_CREATOR_CHECKED);
    assert(saved.socket_uid == fake_uid && updates == 2 && storage_reads == 1);
    record_local_socket_creator(&skb, &key);
    assert(updates == 2 && storage_reads == 1);

    // A non-full packet cannot establish a negative, even if the cached
    // assignment already contains an earlier valid cgroup ID and billing UID.
    reset();
    storage_present = false;
    saved_present = true;
    saved.socket_cookie = fake_cookie;
    saved.socket_cgroup_id = fake_cgroup;
    saved.socket_uid = fake_uid;
    saved.identity_flags = SB_TC_IDENTITY_VALID;
    fake_cgroup = 0;
    record_local_socket_creator(&skb, &key);
    assert(!(saved.identity_flags & SB_TC_IDENTITY_CREATOR_CHECKED));
    assert(storage_reads == 1 && updates == 0);
    fake_cgroup = 202;
    storage_present = true;
    record_local_socket_creator(&skb, &key);
    assert(socket_creator_valid(&saved.creator, fake_cookie));
    assert(storage_reads == 2 && updates == 1);

    // A tuple reused by a different cookie drops every old identity field.
    saved.path = SB_TC_PATH_DELIVERY;
    saved.ifindex = 77;
    fake_cookie++;
    fake_cgroup = 0;
    storage_present = false;
    record_local_socket_creator(&skb, &key);
    assert(saved.socket_cookie == fake_cookie && saved.path == 0 && saved.ifindex == 0);
    assert(saved.identity_flags == 0 && saved.socket_uid == 0 && saved.socket_cgroup_id == 0);
    assert(memcmp(&saved.creator, &(struct sb_socket_creator){}, sizeof(storage)) == 0);
    storage_present = true;
    storage.cookie = fake_cookie;
    record_local_socket_creator(&skb, &key);
    assert(socket_creator_valid(&saved.creator, fake_cookie));

    for (int field = 0; field < 6; ++field) {
        reset();
        switch (field) {
        case 0: storage.flags = 0; break;
        case 1: storage.cookie = 0; break;
        case 2: storage.cookie++; break;
        case 3: storage.start_time_ns = 0; break;
        case 4: storage.process_id = 0; break;
        case 5: storage.thread_id = 0; break;
        }
        record_local_socket_creator(&skb, &key);
        assert(saved.creator.flags == 0);
        assert(!(saved.identity_flags & SB_TC_IDENTITY_CREATOR_CHECKED));
        storage = (struct sb_socket_creator){.cookie = fake_cookie, .start_time_ns = 999,
            .process_id = 44, .thread_id = 45, .flags = SB_SOCKET_CREATOR_VALID};
        record_local_socket_creator(&skb, &key);
        assert(socket_creator_valid(&saved.creator, fake_cookie));
        assert(storage_reads == 2);
    }
    reset();
    fake_cookie = 0;
    record_local_socket_creator(&skb, &key);
    assert(!saved_present && storage_reads == 0 && updates == 0);

    reset();
    record_local_socket_creator(&skb, &key);
    assert(build_assignment(&value, &saved, 9, mac, SB_TC_PATH_DELIVERY, false));
    assert(memcmp(&value.creator, &saved.creator, sizeof(storage)) == 0);
    assert(value.socket_cookie == saved.socket_cookie && value.socket_uid == saved.socket_uid);
    saved = value;
    assert(!build_assignment(&value, &saved, 9, mac, SB_TC_PATH_DELIVERY, false));
    assert(build_assignment(&value, &saved, 9, mac, SB_TC_PATH_SHARED, false));
    assert(value.socket_cookie == 0 && value.identity_flags == 0);
    assert(memcmp(&value.creator, &(struct sb_socket_creator){}, sizeof(storage)) == 0);
    saved = value;
    saved.creator = storage; // Creator-only stale data still requires a write.
    assert(build_assignment(&value, &saved, 9, mac, SB_TC_PATH_SHARED, false));
    saved = value;
    assert(!build_assignment(&value, &saved, 9, mac, SB_TC_PATH_SHARED, false));

    reset();
    record_local_socket(&skb, &key);
    assert(saved.socket_uid == fake_uid && storage_reads == 0);
    puts("creator state transitions passed (host C helpers; no kernel data plane)");
    return 0;
}
