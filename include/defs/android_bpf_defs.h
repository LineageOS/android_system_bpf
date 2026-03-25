#pragma once

#ifdef ENABLE_LIBBPF

// Either vmlinux.h or linux/types.h must be included before bpf/bpf_helpers.h
#ifdef USE_VMLINUX
// When using vmlinux.h, you can't use any system level headers.
#include <vmlinux.h>
#else
#include <linux/bpf.h>
#include <linux/types.h>
#endif  // USE_VMLINUX
#include <bpf/bpf_helpers.h>

// bpf_helpers.h defines __always_inline using "inline __attribute__((always_inline))".
// To prevent potential "duplicate 'inline' declaration" issues depending on the include order,
// redefine using the cdefs.h definition of __always_inline.
#undef __always_inline
#define __always_inline __attribute__((__always_inline__))

#include <sys/cdefs.h>

#define DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid, mapflags)     \
    struct {                                                                                   \
        __uint(type, BPF_MAP_TYPE_##TYPE);                                                     \
        __uint(map_flags, mapflags);                                                           \
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
    DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid, 0)
#define DEFINE_BPF_MAP_GWO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
    DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid, 0)
#define DEFINE_BPF_MAP_GRO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
    DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid, 0)

#define DEFINE_BPF_RINGBUF(the_map, ValueType, num_entries, usr, grp, md)              \
    struct {                                                                           \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                                            \
        __uint(max_entries, num_entries);                                              \
    } the_map SEC(".maps");                                                            \
                                                                                       \
    static inline __always_inline __unused int bpf_##the_map##_output(ValueType* v) {  \
        return bpf_ringbuf_output(&the_map, v, sizeof(*v), 0);                         \
    };                                                                                 \
                                                                                       \
    static inline __always_inline __unused ValueType* bpf_##the_map##_reserve() {      \
        return bpf_ringbuf_reserve(&the_map, sizeof(ValueType), 0);                    \
    }                                                                                  \
                                                                                       \
    static inline __always_inline __unused void bpf_##the_map##_submit(ValueType* v) { \
        bpf_ringbuf_submit(v, 0);                                                      \
    }

#define DEFINE_BPF_PROG(SECTION_NAME, prog_uid, prog_gid, the_prog) \
    SEC(SECTION_NAME)                                               \
    int the_prog

#define DEFINE_BPF_PROG_KVER(SECTION_NAME, prog_uid, prog_gid, the_prog, kver) \
    DEFINE_BPF_PROG(SECTION_NAME, prog_uid, prog_gid, the_prog)

#define LICENSE(NAME) char _license[] SEC("license") = (NAME)
#define CRITICAL(NAME)

// LLVM eBPF builtins: they directly generate BPF_LD_ABS/BPF_LD_IND (skb may be ignored?)
unsigned long long load_byte(void* skb, unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void* skb, unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void* skb, unsigned long long off) asm("llvm.bpf.load.word");

#else  // LIBBPF DISABLED

#include <bpf_helpers.h>

#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

#endif  // ENABLE_LIBBPF
