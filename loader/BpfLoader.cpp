/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef LOG_TAG
#define LOG_TAG "bpfloader"
#endif

#include <arpa/inet.h>
#include <dirent.h>
#include <elf.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <libbpf_android.h>
#include <log/log.h>
#include "BpfSyscallWrappers.h"
#include "bpf/BpfUtils.h"

using android::base::EndsWith;
using std::string;

// Networking-related program types are limited to the Tethering Apex
// to prevent things from breaking due to conflicts on mainline updates
// (exception made for socket filters, ie. xt_bpf for potential use in iptables,
// or for attaching to sockets directly)
constexpr bpf_prog_type kPlatformAllowedProgTypes[] = {
        BPF_PROG_TYPE_KPROBE,
        BPF_PROG_TYPE_PERF_EVENT,
        BPF_PROG_TYPE_SOCKET_FILTER,
        BPF_PROG_TYPE_TRACEPOINT,
        BPF_PROG_TYPE_UNSPEC,  // Will be replaced with fuse bpf program type
};

constexpr bpf_prog_type kUprobestatsAllowedProgTypes[] = {
        BPF_PROG_TYPE_KPROBE,
};

// see b/162057235. For arbitrary program types, the concern is that due to the lack of
// SELinux access controls over BPF program attachpoints, we have no way to control the
// attachment of programs to shared resources (or to detect when a shared resource
// has one BPF program replace another that is attached there)
constexpr bpf_prog_type kVendorAllowedProgTypes[] = {
        BPF_PROG_TYPE_SOCKET_FILTER,
};

const android::bpf::Location locations[] = {
        // Core operating system
        {
                .dir = "/system/etc/bpf/",
                .prefix = "",
                .allowedProgTypes = kPlatformAllowedProgTypes,
                .allowedProgTypesLength = arraysize(kPlatformAllowedProgTypes),
        },
        // uprobestats
        {
                .dir = "/system/etc/bpf/uprobestats/",
                .prefix = "uprobestats/",
                .allowedProgTypes = kUprobestatsAllowedProgTypes,
                .allowedProgTypesLength = arraysize(kUprobestatsAllowedProgTypes),
        },
        // Vendor operating system
        {
                .dir = "/vendor/etc/bpf/",
                .prefix = "vendor/",
                .allowedProgTypes = kVendorAllowedProgTypes,
                .allowedProgTypesLength = arraysize(kVendorAllowedProgTypes),
        },
};

int loadAllElfObjects(const android::bpf::Location& location) {
    int retVal = 0;
    DIR* dir;
    struct dirent* ent;

    if ((dir = opendir(location.dir)) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            string s = ent->d_name;
            if (!EndsWith(s, ".o")) continue;

            string progPath(location.dir);
            progPath += s;

            bool critical;
            int ret = android::bpf::loadProg(progPath.c_str(), &critical, location);
            if (ret) {
                if (critical) retVal = ret;
                ALOGE("Failed to load object: %s, ret: %s", progPath.c_str(), std::strerror(-ret));
            } else {
                ALOGI("Loaded object: %s", progPath.c_str());
            }
        }
        closedir(dir);
    }
    return retVal;
}

int createSysFsBpfSubDir(const char* const prefix) {
    if (*prefix) {
        mode_t prevUmask = umask(0);

        string s = "/sys/fs/bpf/";
        s += prefix;

        errno = 0;
        int ret = mkdir(s.c_str(), S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO);
        if (ret && errno != EEXIST) {
            const int err = errno;
            ALOGE("Failed to create directory: %s, ret: %s", s.c_str(), std::strerror(err));
            return -err;
        }

        umask(prevUmask);
    }
    return 0;
}

int main(int argc, char** argv) {
    (void)argc;
    android::base::InitLogging(argv, &android::base::KernelLogger);

    // Load all ELF objects, create programs and maps, and pin them
    for (const auto& location : locations) {
        if (createSysFsBpfSubDir(location.prefix) || loadAllElfObjects(location)) {
            ALOGE("=== CRITICAL FAILURE LOADING BPF PROGRAMS FROM %s ===", location.dir);
            ALOGE("If this triggers reliably, you're probably missing kernel options or patches.");
            ALOGE("If this triggers randomly, you might be hitting some memory allocation "
                  "problems or startup script race.");
            ALOGE("--- DO NOT EXPECT SYSTEM TO BOOT SUCCESSFULLY ---");
            sleep(20);
            return 2;
        }
    }

    if (!android::base::SetProperty("bpf.progs_loaded", "1")) {
        ALOGE("Failed to set bpf.progs_loaded property");
        return 1;
    }

    return 0;
}
