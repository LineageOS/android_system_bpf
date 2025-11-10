/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "BpfLoader"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/elf.h>
#include <log/log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "BpfSyscallWrappers.h"
#include "bpf/BpfUtils.h"
#include "bpf_map_def.h"
#include "include/libbpf_android.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/cmsg.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

// Size of the BPF log buffer for verifier logging
#define BPF_LOAD_LOG_SZ 0xfffff

using android::base::EndsWith;
using android::base::StartsWith;
using android::base::unique_fd;
using std::ifstream;
using std::ios;
using std::optional;
using std::strerror;
using std::string;
using std::vector;

namespace android {
namespace bpf {

static unsigned int page_size = static_cast<unsigned int>(getpagesize());

static string pathToObjName(const string& path) {
    // extract everything after the final slash, ie. this is the filename 'foo.o'
    string filename = android::base::Split(path, "/").back();
    // strip off everything from the final period onwards (strip '.o' suffix), ie. 'foo'
    return filename.substr(0, filename.find_last_of('.'));
}

typedef struct {
    enum bpf_prog_type type;
    string name;
    vector<char> data;
    vector<char> rel_data;
    optional<struct bpf_prog_def> prog_def;

    unique_fd prog_fd; // fd after loading
} codeSection;

static bool readElfHeader(ifstream& elfFile, Elf64_Ehdr* eh) {
    elfFile.seekg(0);
    if (elfFile.fail()) return false;
    if (!elfFile.read((char*)eh, sizeof(*eh))) return false;
    return true;
}

// Reads all section header tables into an Shdr array
static int readSectionHeadersAll(ifstream& elfFile, vector<Elf64_Shdr>& shTable) {
    Elf64_Ehdr eh;

    if (!readElfHeader(elfFile, &eh)) return -1;

    elfFile.seekg(eh.e_shoff);
    if (elfFile.fail()) return -1;

    // Read shdr table entries
    shTable.resize(eh.e_shnum);

    if (!elfFile.read((char*)shTable.data(), eh.e_shnum * eh.e_shentsize)) return -1;

    return 0;
}

// Read a section by its index - for ex to get sec hdr strtab blob
static int readSectionByIdx(ifstream& elfFile, int id, vector<char>& sec) {
    vector<Elf64_Shdr> shTable;
    if (readSectionHeadersAll(elfFile, shTable)) return -1;

    elfFile.seekg(shTable[id].sh_offset);
    if (elfFile.fail()) return -1;

    sec.resize(shTable[id].sh_size);
    if (!elfFile.read(sec.data(), shTable[id].sh_size)) return -1;

    return 0;
}

// Read whole section header string table
static int readSectionHeaderStrtab(ifstream& elfFile, vector<char>& strtab) {
    Elf64_Ehdr eh;
    if (!readElfHeader(elfFile, &eh)) return -1;
    if (readSectionByIdx(elfFile, eh.e_shstrndx, strtab)) return -1;
    return 0;
}

// Get name from offset in strtab
static int getSymName(ifstream& elfFile, int nameOff, string& name) {
    vector<char> secStrTab;
    if (readSectionHeaderStrtab(elfFile, secStrTab)) return -1;

    if (nameOff >= (int)secStrTab.size()) return -1;

    name = string(secStrTab.data() + nameOff);
    return 0;
}

// Reads a full section by name - example to get the GPL license
template <typename T>
static int readSectionByName(const char* name, ifstream& elfFile, vector<T>& data) {
    vector<Elf64_Shdr> shTable;
    if (readSectionHeadersAll(elfFile, shTable)) return -1;

    vector<char> secStrTab;
    if (readSectionHeaderStrtab(elfFile, secStrTab)) return -1;

    for (int i = 0; i < (int)shTable.size(); i++) {
        char* secname = secStrTab.data() + shTable[i].sh_name;

        if (!strcmp(secname, name)) {
            elfFile.seekg(shTable[i].sh_offset);
            if (elfFile.fail()) return -1;

            if (shTable[i].sh_size % sizeof(T)) return -1;
            data.resize(shTable[i].sh_size / sizeof(T));
            if (!elfFile.read(reinterpret_cast<char*>(data.data()), shTable[i].sh_size))
                return -1;

            return 0;
        }
    }
    return -2;
}

static int readSectionByType(ifstream& elfFile, int type, vector<char>& data) {
    vector<Elf64_Shdr> shTable;
    if (readSectionHeadersAll(elfFile, shTable)) return -1;

    for (int i = 0; i < (int)shTable.size(); i++) {
        if ((int)shTable[i].sh_type != type) continue;

        elfFile.seekg(shTable[i].sh_offset);
        if (elfFile.fail()) return -1;

        data.resize(shTable[i].sh_size);
        if (!elfFile.read(data.data(), shTable[i].sh_size)) return -1;

        return 0;
    }
    return -2;
}

static bool symCompare(Elf64_Sym a, Elf64_Sym b) {
    return (a.st_value < b.st_value);
}

static int readSymTab(ifstream& elfFile, int sort, vector<Elf64_Sym>& data) {
    vector<char> secData;
    int ret = readSectionByType(elfFile, SHT_SYMTAB, secData);
    if (ret) return ret;

    Elf64_Sym* buf = (Elf64_Sym*)secData.data();
    int numElems = secData.size() / sizeof(Elf64_Sym);
    data.assign(buf, buf + numElems);

    if (sort) std::sort(data.begin(), data.end(), symCompare);
    return 0;
}

static int readProgDefs(ifstream& elfFile, vector<struct bpf_prog_def>& pd) {
    return readSectionByName("progs", elfFile, pd);
}

static int getSectionSymNames(ifstream& elfFile, const string& sectionName, vector<string>& names,
                              optional<unsigned> symbolType = std::nullopt) {
    int ret;
    string name;
    vector<Elf64_Sym> symtab;
    vector<Elf64_Shdr> shTable;

    ret = readSymTab(elfFile, 1 /* sort */, symtab);
    if (ret) return ret;

    // Get index of section
    ret = readSectionHeadersAll(elfFile, shTable);
    if (ret) return ret;

    int sec_idx = -1;
    for (int i = 0; i < (int)shTable.size(); i++) {
        ret = getSymName(elfFile, shTable[i].sh_name, name);
        if (ret) return ret;

        if (!name.compare(sectionName)) {
            sec_idx = i;
            break;
        }
    }

    // No section found with matching name
    if (sec_idx == -1) {
        ALOGW("No %s section could be found in elf object", sectionName.c_str());
        return -1;
    }

    for (int i = 0; i < (int)symtab.size(); i++) {
        if (symbolType.has_value() && ELF_ST_TYPE(symtab[i].st_info) != symbolType) continue;

        if (symtab[i].st_shndx == sec_idx) {
            string s;
            ret = getSymName(elfFile, symtab[i].st_name, s);
            if (ret) return ret;
            names.push_back(s);
        }
    }

    return 0;
}

// Read a section by its index - for ex to get sec hdr strtab blob
static int readCodeSections(ifstream& elfFile, vector<codeSection>& cs) {
    vector<Elf64_Shdr> shTable;
    int entries, ret = 0;

    ret = readSectionHeadersAll(elfFile, shTable);
    if (ret) return ret;
    entries = shTable.size();

    vector<struct bpf_prog_def> pd;
    ret = readProgDefs(elfFile, pd);
    if (ret) return ret;
    vector<string> progDefNames;
    ret = getSectionSymNames(elfFile, "progs", progDefNames);
    if (!pd.empty() && ret) return ret;

    for (int i = 0; i < entries; i++) {
        string name;
        codeSection cs_temp;
        cs_temp.type = BPF_PROG_TYPE_UNSPEC;

        ret = getSymName(elfFile, shTable[i].sh_name, name);
        if (ret) return ret;

        if (!StartsWith(name, "skfilter/")) continue;

        string oldName = name;

        // convert all slashes to underscores
        std::replace(name.begin(), name.end(), '/', '_');

        cs_temp.type = BPF_PROG_TYPE_SOCKET_FILTER;
        cs_temp.name = name;

        ret = readSectionByIdx(elfFile, i, cs_temp.data);
        if (ret) return ret;
        ALOGV("Loaded code section %d (%s)", i, name.c_str());

        vector<string> csSymNames;
        ret = getSectionSymNames(elfFile, oldName, csSymNames, STT_FUNC);
        if (ret || !csSymNames.size()) return ret;
        for (size_t j = 0; j < progDefNames.size(); ++j) {
            if (!progDefNames[j].compare(csSymNames[0] + "_def")) {
                cs_temp.prog_def = pd[j];
                break;
            }
        }

        // Check for rel section
        if (cs_temp.data.size() > 0 && i < entries) {
            ret = getSymName(elfFile, shTable[i + 1].sh_name, name);
            if (ret) return ret;

            if (name == (".rel" + oldName)) {
                ret = readSectionByIdx(elfFile, i + 1, cs_temp.rel_data);
                if (ret) return ret;
                ALOGV("Loaded relo section %d (%s)", i, name.c_str());
            }
        }

        if (cs_temp.data.size() > 0) {
            cs.push_back(std::move(cs_temp));
            ALOGV("Adding section %d to cs list", i);
        }
    }
    return 0;
}

static int getSymNameByIdx(ifstream& elfFile, int index, string& name) {
    vector<Elf64_Sym> symtab;
    int ret = 0;

    ret = readSymTab(elfFile, 0 /* !sort */, symtab);
    if (ret) return ret;

    if (index >= (int)symtab.size()) return -1;

    return getSymName(elfFile, symtab[index].st_name, name);
}

static int createMaps(const char* elfPath, ifstream& elfFile, vector<unique_fd>& mapFds) {
    int ret;
    vector<struct bpf_map_def> md;
    vector<string> mapNames;
    string objName = pathToObjName(string(elfPath));

    ret = readSectionByName("maps", elfFile, md);
    if (ret == -2) return 0;  // no maps to read
    if (ret) return ret;

    ret = getSectionSymNames(elfFile, "maps", mapNames);
    if (ret) return ret;

    unsigned kvers = kernelVersion();

    for (int i = 0; i < (int)mapNames.size(); i++) {
        if (md[i].zero != 0) abort();

        if (kvers < md[i].min_kver) {
            ALOGD("skipping map %s which requires kernel version 0x%x >= 0x%x",
                  mapNames[i].c_str(), kvers, md[i].min_kver);
            mapFds.push_back(unique_fd());
            continue;
        }

        if (kvers >= md[i].max_kver) {
            ALOGD("skipping map %s which requires kernel version 0x%x < 0x%x",
                  mapNames[i].c_str(), kvers, md[i].max_kver);
            mapFds.push_back(unique_fd());
            continue;
        }

        // The .h file enforces that this is a power of two, and page size will
        // also always be a power of two, so this logic is actually enough to
        // force it to be a multiple of the page size, as required by the kernel.
        unsigned int max_entries = md[i].max_entries;
        if (md[i].type == BPF_MAP_TYPE_RINGBUF) {
            if (max_entries < page_size) max_entries = page_size;
        }

        // Format of pin location is /sys/fs/bpf/<prefix>map_<objName>_<mapName>
        // except that maps shared across .o's have empty <objName>
        // Note: <objName> refers to the extension-less basename of the .o file (without @ suffix).
        string mapPinLoc = string("/sys/fs/bpf/vendor/map_") +
                           (md[i].shared ? "" : objName) + "_" + mapNames[i];
        bool reuse = false;
        unique_fd fd;
        int saved_errno;

        if (access(mapPinLoc.c_str(), F_OK) == 0) {
            fd.reset(mapRetrieveRO(mapPinLoc.c_str()));
            saved_errno = errno;
            ALOGV("bpf_create_map reusing map %s, ret: %d", mapNames[i].c_str(), fd.get());
            reuse = true;
        } else {
            union bpf_attr req = {
              .map_type = md[i].type,
              .key_size = md[i].key_size,
              .value_size = md[i].value_size,
              .max_entries = max_entries,
              .map_flags = md[i].map_flags,
            };
            strlcpy(req.map_name, mapNames[i].c_str(), sizeof(req.map_name));
            fd.reset(bpf(BPF_MAP_CREATE, req));
            saved_errno = errno;
            ALOGV("bpf_create_map name %s, ret: %d", mapNames[i].c_str(), fd.get());
        }

        if (!fd.ok()) return -saved_errno;

        if (!reuse) {
            ret = bpfFdPin(fd, mapPinLoc.c_str());
            if (ret) {
                int err = errno;
                ALOGE("pin %s -> %d [%d:%s]", mapPinLoc.c_str(), ret, err, strerror(err));
                return -err;
            }
            ret = chmod(mapPinLoc.c_str(), md[i].mode);
            if (ret) {
                int err = errno;
                ALOGE("chmod(%s, 0%o) = %d [%d:%s]", mapPinLoc.c_str(), md[i].mode, ret, err,
                      strerror(err));
                return -err;
            }
            ret = chown(mapPinLoc.c_str(), (uid_t)md[i].uid, (gid_t)md[i].gid);
            if (ret) {
                int err = errno;
                ALOGE("chown(%s, %u, %u) = %d [%d:%s]", mapPinLoc.c_str(), md[i].uid, md[i].gid,
                      ret, err, strerror(err));
                return -err;
            }
        }

        mapFds.push_back(std::move(fd));
    }

    return ret;
}

static void applyRelo(void* insnsPtr, Elf64_Addr offset, int fd) {
    int insnIndex;
    struct bpf_insn *insn, *insns;

    insns = (struct bpf_insn*)(insnsPtr);

    insnIndex = offset / sizeof(struct bpf_insn);
    insn = &insns[insnIndex];

    // Occasionally might be useful for relocation debugging, but pretty spammy
    if (0) {
        ALOGV("applying relo to instruction at byte offset: %llu, "
              "insn offset %d, insn %llx",
              (unsigned long long)offset, insnIndex, *(unsigned long long*)insn);
    }

    if (insn->code != (BPF_LD | BPF_IMM | BPF_DW)) {
        ALOGE("invalid relo for insn %d: code 0x%x", insnIndex, insn->code);
        return;
    }

    insn->imm = fd;
    insn->src_reg = BPF_PSEUDO_MAP_FD;
}

static void applyMapRelo(ifstream& elfFile, vector<unique_fd> &mapFds, vector<codeSection>& cs) {
    vector<string> mapNames;

    int ret = getSectionSymNames(elfFile, "maps", mapNames);
    if (ret) return;

    for (int k = 0; k != (int)cs.size(); k++) {
        Elf64_Rel* rel = (Elf64_Rel*)(cs[k].rel_data.data());
        int n_rel = cs[k].rel_data.size() / sizeof(*rel);

        for (int i = 0; i < n_rel; i++) {
            int symIndex = ELF64_R_SYM(rel[i].r_info);
            string symName;

            ret = getSymNameByIdx(elfFile, symIndex, symName);
            if (ret) return;

            // Find the map fd and apply relo
            for (int j = 0; j < (int)mapNames.size(); j++) {
                if (!mapNames[j].compare(symName)) {
                    applyRelo(cs[k].data.data(), rel[i].r_offset, mapFds[j]);
                    break;
                }
            }
        }
    }
}

static int loadCodeSections(const char* elfPath, vector<codeSection>& cs, const string& license) {
    unsigned kvers = kernelVersion();

    if (!kvers) {
        ALOGE("unable to get kernel version");
        return -EINVAL;
    }

    string objName = pathToObjName(string(elfPath));

    for (int i = 0; i < (int)cs.size(); i++) {
        unique_fd& fd = cs[i].prog_fd;
        int ret;
        string name = cs[i].name;

        if (!cs[i].prog_def.has_value()) {
            ALOGE("[%d] '%s' missing program definition! bad bpf.o build?", i, name.c_str());
            return -EINVAL;
        }

        unsigned min_kver = cs[i].prog_def->min_kver;
        unsigned max_kver = cs[i].prog_def->max_kver;
        if (kvers < min_kver || kvers >= max_kver) {
            ALOGD("skipping program cs[%d].name:%s min_kver:%x max_kver:%x (kvers:%x)",
                  i, name.c_str(), min_kver, max_kver, kvers);
            continue;
        }

        // strip any potential $foo suffix
        // this can be used to provide duplicate programs
        // conditionally loaded based on running kernel version
        name = name.substr(0, name.find_last_of('$'));

        bool reuse = false;
        // Format of pin location is
        // /sys/fs/bpf/<prefix>prog_<objName>_<progName>
        string progPinLoc = string("/sys/fs/bpf/vendor/prog_") + objName + '_' + name;
        if (access(progPinLoc.c_str(), F_OK) == 0) {
            fd.reset(retrieveProgram(progPinLoc.c_str()));
            ALOGV("New bpf prog load reusing prog %s, ret: %d (%s)", progPinLoc.c_str(), fd.get(),
                  (!fd.ok() ? std::strerror(errno) : "no error"));
            reuse = true;
        } else {
            vector<char> log_buf(BPF_LOAD_LOG_SZ, 0);

            union bpf_attr req = {
              .prog_type = cs[i].type,
              .kern_version = kvers,
              .license = ptr_to_u64(license.c_str()),
              .insns = ptr_to_u64(cs[i].data.data()),
              .insn_cnt = static_cast<__u32>(cs[i].data.size() / sizeof(struct bpf_insn)),
              .log_level = 1,
              .log_buf = ptr_to_u64(log_buf.data()),
              .log_size = static_cast<__u32>(log_buf.size()),
            };
            strlcpy(req.prog_name, cs[i].name.c_str(), sizeof(req.prog_name));
            fd.reset(bpf(BPF_PROG_LOAD, req));

            if (!fd.ok()) {
                ALOGW("BPF_PROG_LOAD call for %s (%s) returned fd: %d (%s)", elfPath,
                      cs[i].name.c_str(), fd.get(), std::strerror(errno));

                vector<string> lines = android::base::Split(log_buf.data(), "\n");

                ALOGW("BPF_PROG_LOAD - BEGIN log_buf contents:");
                for (const auto& line : lines) ALOGW("%s", line.c_str());
                ALOGW("BPF_PROG_LOAD - END log_buf contents.");

                if (cs[i].prog_def->optional) {
                    ALOGW("failed program is marked optional - continuing...");
                    continue;
                }
                ALOGE("non-optional program failed to load.");
            }
        }

        if (!fd.ok()) return fd.get();

        if (!reuse) {
            ret = bpfFdPin(fd, progPinLoc.c_str());
            if (ret) {
                int err = errno;
                ALOGE("create %s -> %d [%d:%s]", progPinLoc.c_str(), ret, err, strerror(err));
                return -err;
            }
            if (chmod(progPinLoc.c_str(), 0440)) {
                int err = errno;
                ALOGE("chmod %s 0440 -> [%d:%s]", progPinLoc.c_str(), err, strerror(err));
                return -err;
            }
            if (chown(progPinLoc.c_str(), (uid_t)cs[i].prog_def->uid,
                      (gid_t)cs[i].prog_def->gid)) {
                int err = errno;
                ALOGE("chown %s %d %d -> [%d:%s]", progPinLoc.c_str(), cs[i].prog_def->uid,
                      cs[i].prog_def->gid, err, strerror(err));
                return -err;
            }
        }
    }

    return 0;
}

int loadProg(const char* elfPath, bool* isCritical) {
    vector<char> license;
    vector<char> critical;
    vector<codeSection> cs;
    vector<unique_fd> mapFds;
    int ret;

    if (!isCritical) return -1;
    *isCritical = false;

    ifstream elfFile(elfPath, ios::in | ios::binary);
    if (!elfFile.is_open()) return -1;

    ret = readSectionByName("critical", elfFile, critical);
    *isCritical = !ret;

    ret = readSectionByName("license", elfFile, license);
    if (ret) {
        ALOGE("Couldn't find license in %s", elfPath);
        return ret;
    }

    ALOGI("Platform BpfLoader loading %s%s ELF object %s with license %s",
          *isCritical ? "critical for " : "optional", *isCritical ? (char*)critical.data() : "",
          elfPath, (char*)license.data());

    ret = readCodeSections(elfFile, cs);
    if (ret) {
        ALOGE("Couldn't read all code sections in %s", elfPath);
        return ret;
    }

    ret = createMaps(elfPath, elfFile, mapFds);
    if (ret) {
        ALOGE("Failed to create maps: (ret=%d) in %s", ret, elfPath);
        return ret;
    }

    for (int i = 0; i < (int)mapFds.size(); i++)
        ALOGV("map_fd found at %d is %d in %s", i, mapFds[i].get(), elfPath);

    applyMapRelo(elfFile, mapFds, cs);

    ret = loadCodeSections(elfPath, cs, string(license.data()));
    if (ret) ALOGE("Failed to load programs, loadCodeSections ret=%d", ret);

    return ret;
}

int loadAllElfObjects() {
    int retVal = 0;
    DIR* dir;
    struct dirent* ent;

    if ((dir = opendir("/vendor/etc/bpf/")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            string s = ent->d_name;
            if (!EndsWith(s, ".o")) continue;

            string progPath("/vendor/etc/bpf/");
            progPath += s;

            bool critical;
            int ret = loadProg(progPath.c_str(), &critical);
            if (ret) {
                if (critical) retVal = ret;
                ALOGE("Failed to load object: %s, ret: %s", progPath.c_str(), strerror(-ret));
            } else {
                ALOGV("Loaded object: %s", progPath.c_str());
            }
        }
        closedir(dir);
    }
    return retVal;
}

}  // namespace bpf
}  // namespace android

// ----- extern C stuff for rust below here -----

void vendorBpfLoader() {
    // since we only ever get called from mainline NetBpfLoad
    // (see packages/modules/Connectivity/netbpfload/NetBpfLoad.cpp around line 516)
    // and there no arguments, so we can just pretend/assume this is the case.
    const char* argv[] = {"/system/bin/bpfloader", NULL};
    android::base::InitLogging(const_cast<char**>(argv), &android::base::KernelLogger);

    // Load all ELF objects, create programs and maps, and pin them
    if (android::bpf::loadAllElfObjects()) {
        ALOGE("=== CRITICAL FAILURE LOADING BPF PROGRAMS FROM /vendor/etc/bpf ===");
        ALOGE("If this triggers reliably, you're probably missing kernel options or patches.");
        ALOGE("If this triggers randomly, you might be hitting some memory allocation "
              "problems or startup script race.");
        ALOGE("--- DO NOT EXPECT SYSTEM TO BOOT SUCCESSFULLY ---");
        sleep(20);
        exit(121);
    }

    const char* args[] = {"/apex/com.android.tethering/bin/netbpfload", "done", NULL};
    execve(args[0], (char**)args, environ);
    ALOGE("FATAL: execve(): %d[%s]", errno, strerror(errno));
    exit(122);
}
