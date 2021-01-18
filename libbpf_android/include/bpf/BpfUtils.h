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

#ifndef BPF_BPFUTILS_H
#define BPF_BPFUTILS_H

#include <linux/if_ether.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <string>

#include "BpfSyscallWrappers.h"

namespace android {
namespace bpf {

enum class BpfLevel {
    // Devices shipped before P or kernel version is lower than 4.9 do not
    // have eBPF enabled.
    NONE,
    // Devices shipped in P with android 4.9 kernel only have the basic eBPF
    // functionalities such as xt_bpf and cgroup skb filter.
    BASIC_4_9,
    // For devices that have 4.14 kernel. It supports advanced features like
    // map_in_map and cgroup socket filter.
    EXTENDED_4_14,
    EXTENDED_4_19,
    EXTENDED_5_4,
};

constexpr const int OVERFLOW_COUNTERSET = 2;

constexpr const uint64_t NONEXISTENT_COOKIE = 0;

constexpr const int MINIMUM_API_REQUIRED = 28;

uint64_t getSocketCookie(int sockFd);
int synchronizeKernelRCU();
int setrlimitForTest();
unsigned kernelVersion();
std::string BpfLevelToString(BpfLevel BpfLevel);
BpfLevel getBpfSupportLevel();

inline bool isBpfSupported() {
    return getBpfSupportLevel() != BpfLevel::NONE;
}

#define SKIP_IF_BPF_NOT_SUPPORTED                                                    \
    do {                                                                             \
        if (!android::bpf::isBpfSupported()) {                                       \
            GTEST_LOG_(INFO) << "This test is skipped since bpf is not available\n"; \
            return;                                                                  \
        }                                                                            \
    } while (0)

#define SKIP_IF_BPF_SUPPORTED                       \
    do {                                            \
        if (android::bpf::isBpfSupported()) return; \
    } while (0)

#define SKIP_IF_EXTENDED_BPF_NOT_SUPPORTED                                                \
    do {                                                                                  \
        if (android::bpf::getBpfSupportLevel() < android::bpf::BpfLevel::EXTENDED_4_14) { \
            GTEST_LOG_(INFO) << "This test is skipped since extended bpf feature"         \
                             << "not supported\n";                                        \
            return;                                                                       \
        }                                                                                 \
    } while (0)

}  // namespace bpf
}  // namespace android

#endif
