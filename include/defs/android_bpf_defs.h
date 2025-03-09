#pragma once

#ifdef ENABLE_LIBBPF

// Either vmlinux.h or linux/types.h must be included before bpf/bpf_helpers.h
#ifdef USE_VMLINUX
// When using vmlinux.h, you can't use any system level headers.
#include <vmlinux.h>
#else
#include <linux/types.h>
#endif  // USE_VMLINUX
#include <bpf/bpf_helpers.h>

#define DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)               \
    struct {                                                                                   \
        __uint(type, BPF_MAP_TYPE_##TYPE);                                                     \
        __type(key, KeyType);                                                                  \
        __type(value, ValueType);                                                              \
        __uint(max_entries, num_entries);                                                      \
    } the_map SEC(".maps");                                                                    \
                                                                                               \
    static inline __always_inline __unused ValueType* bpf_##the_map##_lookup_elem(             \
            const KeyType* k) {                                                                \
        return bpf_map_lookup_elem(&the_map, k);                                               \
    };                                                                                         \
                                                                                               \
    static inline __always_inline __unused int bpf_##the_map##_update_elem(                    \
            const KeyType* k, const ValueType* v, unsigned long long flags) {                  \
        return bpf_map_update_elem(&the_map, k, v, flags);                                     \
    };                                                                                         \
                                                                                               \
    static inline __always_inline __unused int bpf_##the_map##_delete_elem(const KeyType* k) { \
        return bpf_map_delete_elem(&the_map, k);                                               \
    };

#define DEFINE_BPF_MAP_GRW(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
    DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)
#define DEFINE_BPF_MAP_GWO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
    DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)
#define DEFINE_BPF_MAP_GRO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
    DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)

#define DEFINE_BPF_PROG(SECTION_NAME, prog_uid, prog_gid, the_prog) \
    SEC(SECTION_NAME)                                               \
    int the_prog

#define LICENSE(NAME) char _license[] SEC("license") = (NAME)

#else  // LIBBPF DISABLED

#include <bpf_helpers.h>

#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

#endif  // ENABLE_LIBBPF
