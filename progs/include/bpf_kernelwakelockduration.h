/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>

// Number of bits reserved for the counter of in progress kernel wakelocks.
// As defined in the kernel in common/drivers/base/power/wakeup.c.
#define IN_PROGRESS_BITS (sizeof(int) * 4)
#define MAX_IN_PROGRESS ((1 << IN_PROGRESS_BITS) - 1)

#ifdef __cplusplus
static const char kWakeupActivateProgPath[] =
        "/sys/fs/bpf/kernelwakelockduration/"
        "prog_kernelWakelockDuration_tracepoint_power_wakeup_source_activate";
static const char kWakeupDeactivateProgPath[] =
        "/sys/fs/bpf/kernelwakelockduration/"
        "prog_kernelWakelockDuration_tracepoint_power_wakeup_source_deactivate";
static const char kProgramStateMapPath[] =
        "/sys/fs/bpf/kernelwakelockduration/map_kernelWakelockDuration_program_state";
#endif

struct kernel_wakelock_duration_program_state {
    // Internal state used to keep track of the initialization state.
    // If it is 0 it means that the programs haven't processed any event yet.
    // If it is equal to UINT_MAX it means that the programs are fully initialized.
    // Otherwise, it is equal to the `cec` value of the event used to initialize the programs.
    uint64_t program_init;

    // Represents the total time the kernel held at least a wakelock.
    // If it is negative, there are currently active kernel wakelocks and, summing the current ktime
    // would give the accumulated total time plus the duration of the current "active period" (time
    // elapsed from the last time the kernel wakelocks count went from 0 to 1).
    int64_t timer_state_ns;
};
