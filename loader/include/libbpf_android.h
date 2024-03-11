/*
 * Copyright (C) 2018 The Android Open Source Project
 * Android BPF library - public API
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

#include <linux/bpf.h>

#include <fstream>

namespace android {
namespace bpf {

struct Location {
    const char* const dir = "";
    const char* const prefix = "";
    const bpf_prog_type* allowedProgTypes = nullptr;
    size_t allowedProgTypesLength = 0;
};

// BPF loader implementation. Loads an eBPF ELF object
int loadProg(const char* elfPath, bool* isCritical, const Location &location = {});

// Exposed for testing
unsigned int readSectionUint(const char* name, std::ifstream& elfFile, unsigned int defVal);

}  // namespace bpf
}  // namespace android
