/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

/* This file is separate because it's included both by eBPF programs (via include
 * in bpf_helpers.h) and directly by the boot time bpfloader (Loader.cpp).
 */

#include <linux/bpf.h>

// Pull in AID_* constants from //system/core/libcutils/include/private/android_filesystem_config.h
#include <private/android_filesystem_config.h>

/******************************************************************************
 *                                                                            *
 *                          ! ! ! W A R N I N G ! ! !                         *
 *                                                                            *
 * CHANGES TO THESE STRUCTURE DEFINITIONS OUTSIDE OF AOSP/MASTER *WILL* BREAK *
 * MAINLINE MODULE COMPATIBILITY                                              *
 *                                                                            *
 * AND THUS MAY RESULT IN YOUR DEVICE BRICKING AT SOME ARBITRARY POINT IN     *
 * THE FUTURE                                                                 *
 *                                                                            *
 * (and even in aosp/master you may only append new fields at the very end,   *
 *  you may *never* delete fields, change their types, ordering, insert in    *
 *  the middle, etc.  If a mainline module using the old definition has       *
 *  already shipped (which happens roughly monthly), then it's set in stone)  *
 *                                                                            *
 ******************************************************************************/

// For now we default to v0.0 format
#ifndef BPFLOADER_VERSION
#define BPFLOADER_VERSION 0u
#endif

// These are the values used if these fields are missing
#define DEFAULT_BPFLOADER_MIN_VER 0u        // v0.0 (this is inclusive ie. >= v0.0)
#define DEFAULT_BPFLOADER_MAX_VER 0x10000u  // v1.0 (this is exclusive ie. < v1.0)
#define DEFAULT_SIZEOF_BPF_MAP_DEF 32       // v0.0 struct: enum + alignment padding + 7 uint
#define DEFAULT_SIZEOF_BPF_PROG_DEF 20      // v0.0 struct: 4 uint + bool + alignment padding

/*
 * Map structure to be used by Android eBPF C programs. The Android eBPF loader
 * uses this structure from eBPF object to create maps at boot time.
 *
 * The eBPF C program should define structure in the maps section using
 * SEC("maps") otherwise it will be ignored by the eBPF loader.
 *
 * For example:
 *   const struct bpf_map_def SEC("maps") mymap { .type=... , .key_size=... }
 *
 * See 'bpf_helpers.h' for helpful macros for eBPF program use.
 */
struct bpf_map_def {
    enum bpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;

    // The following are not supported by the Android bpfloader:
    //   unsigned int inner_map_idx;
    //   unsigned int numa_node;

    unsigned int uid;   // uid_t
    unsigned int gid;   // gid_t
    unsigned int mode;  // mode_t

#if BPFLOADER_VERSION >= 1u
    // The following fields were added in version 0.1
    unsigned int bpfloader_min_ver;  // if missing, defaults to 0, ie. v0.0
    unsigned int bpfloader_max_ver;  // if missing, defaults to 0x10000, ie. v1.0
#endif
};

struct bpf_prog_def {
    unsigned int uid;
    unsigned int gid;

    // kernelVersion() must be >= min_kver and < max_kver
    unsigned int min_kver;
    unsigned int max_kver;

    bool optional;  // program section (ie. function) may fail to load, continue onto next func.

#if BPFLOADER_VERSION >= 1u
    // The following fields were added in version 0.1
    unsigned int bpfloader_min_ver;  // if missing, defaults to 0, ie. v0.0
    unsigned int bpfloader_max_ver;  // if missing, defaults to 0x10000, ie. v1.0
#endif
};
