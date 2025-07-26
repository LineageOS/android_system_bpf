/*
 * Copyright (C) 2024 The Android Open Source Project
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

//! BPF loader for system and vendor applications

use android_ids::{AID_GRAPHICS, AID_MEDIA_RW, AID_ROOT, AID_SYSTEM};
use android_logger::AndroidLogger;
use anyhow::{anyhow, ensure};
use libbpf_rs::{
    set_print, AsRawLibbpf, MapCore, ObjectBuilder, OpenObject, OpenProgramMut, PrintLevel,
    ProgramType,
};
use libbpf_sys::{bpf_map__autocreate, bpf_program__set_type};
use libc::{
    mode_t, uname, utsname, S_IRGRP, S_IROTH, S_IRUSR, S_IRWXG, S_IRWXO, S_IRWXU, S_ISVTX, S_IWGRP,
    S_IWOTH, S_IWUSR,
};
use log::{debug, error, info, warn, Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use rustutils::system_properties;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::{
    cmp::max,
    env, fs,
    fs::{File, Permissions},
    io::{LineWriter, Write},
    os::fd::FromRawFd,
    os::unix::fs::{chown, PermissionsExt},
    panic,
    path::Path,
    sync::{Arc, Mutex},
};

const fn kver(a: u32, b: u32, c: u32) -> u32 {
    (a << 24) + (b << 16) + c
}

const KVER_NONE: u32 = kver(0, 0, 0);
const KVER_INF: u32 = 0xFFFFFFFF;
const KVER_5_10: u32 = kver(5, 10, 0);
const KVER_6_1: u32 = kver(6, 1, 0);

enum KernelLevel {
    // Commented out unused due to rust complaining...
    // EMERG = 0,
    // ALERT = 1,
    // CRIT = 2,
    ERR = 3,
    WARNING = 4,
    // NOTICE = 5,
    INFO = 6,
    DEBUG = 7,
}

fn level_to_kern_level(level: &Level) -> u8 {
    let result = match level {
        Level::Error => KernelLevel::ERR,
        Level::Warn => KernelLevel::WARNING,
        Level::Info => KernelLevel::INFO,
        Level::Debug => KernelLevel::DEBUG,
        Level::Trace => KernelLevel::DEBUG,
    };
    result as u8
}

/// A logger implementation to enable bpfloader to write to kmsg on error as
/// bpfloader runs at early init prior to the availability of standard Android
/// logging. If a crash were to occur, we can disrupt boot, and therefore we
/// need the ability to access the logs on the serial port.
pub struct BpfKmsgLogger {
    log_level: LevelFilter,
    tag: String,
    kmsg_writer: Arc<Mutex<Box<dyn Write + Send>>>,
    a_logger: AndroidLogger,
}

impl Log for BpfKmsgLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.log_level || self.a_logger.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        if record.metadata().level() <= self.log_level {
            let mut writer = self.kmsg_writer.lock().unwrap();
            write!(
                writer,
                "<{}>{}: {}",
                level_to_kern_level(&record.level()),
                self.tag,
                record.args()
            )
            .unwrap();
            let _ = writer.flush();
        }
        self.a_logger.log(record);
    }

    fn flush(&self) {}
}

impl BpfKmsgLogger {
    /// Initialize the logger
    pub fn init(kmsg_file: File) -> Result<(), SetLoggerError> {
        let alog_level = LevelFilter::Info;
        let kmsg_level = LevelFilter::Error;

        let log_config = android_logger::Config::default()
            .with_tag("BpfLoader-rs")
            .with_max_level(alog_level)
            .with_log_buffer(android_logger::LogId::Main)
            .format(|buf, record| writeln!(buf, "{}", record.args()));

        let writer = Box::new(LineWriter::new(kmsg_file)) as Box<dyn Write + Send>;
        log::set_max_level(max(alog_level, kmsg_level));
        log::set_boxed_logger(Box::new(BpfKmsgLogger {
            log_level: kmsg_level,
            tag: "BpfLoader-rs".to_string(),
            kmsg_writer: Arc::new(Mutex::new(writer)),
            a_logger: AndroidLogger::new(log_config),
        }))
    }
}

fn libbpf_print(level: PrintLevel, mut msg: String) {
    if msg.ends_with('\n') {
        msg.pop();
    }
    match level {
        PrintLevel::Debug => debug!("{}", msg),
        PrintLevel::Info => info!("{}", msg),
        PrintLevel::Warn => warn!("{}", msg),
    }
}

struct MapDesc {
    name: &'static str,
    perms: mode_t,
    owner: u32,
    group: u32,
    // Map is loaded if kernel_version() is >= min_kver and < max_kver
    min_kver: u32,
    max_kver: u32,
}

impl MapDesc {
    pub const fn new(group: u32, perms: mode_t, name: &'static str) -> Self {
        MapDesc { name, perms, owner: AID_ROOT, group, min_kver: KVER_NONE, max_kver: KVER_INF }
    }

    pub const fn new_kver(group: u32, perms: mode_t, min_kver: u32, name: &'static str) -> Self {
        MapDesc { name, perms, owner: AID_ROOT, group, min_kver, max_kver: KVER_INF }
    }
}

struct ProgDesc {
    name: &'static str,
    owner: u32,
    group: u32,
    // Prog is loaded if kernel_version() is >= min_kver and < max_kver
    min_kver: u32,
    max_kver: u32,
}

impl ProgDesc {
    pub const fn new(group: u32, name: &'static str) -> Self {
        ProgDesc { name, owner: AID_ROOT, group, min_kver: KVER_NONE, max_kver: KVER_INF }
    }

    pub const fn new_kver(group: u32, min_kver: u32, name: &'static str) -> Self {
        ProgDesc { name, owner: AID_ROOT, group, min_kver, max_kver: KVER_INF }
    }
}

struct BpfFileDesc {
    filename: &'static str,
    // Maps and Progs are pinned under /sys/fs/bpf/<prefix>.
    prefix: &'static str,
    // Warning: setting this to 'true' will cause the system to boot loop if there are any issues
    // loading the bpf program.
    critical: bool,
    // If this is true, maps and programs in the bpf object file are not loaded.
    skip_on_user: bool,
    maps: &'static [MapDesc],
    progs: &'static [ProgDesc],
}

const PERM_GRW: mode_t = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
const PERM_GRO: mode_t = S_IRUSR | S_IWUSR | S_IRGRP;
const PERM_GWO: mode_t = S_IRUSR | S_IWUSR | S_IWGRP;
const PERM_UGR: mode_t = S_IRUSR | S_IRGRP;
const PERM_ORW: mode_t = PERM_GRW | S_IROTH | S_IWOTH;
const PERM_ORO: mode_t = PERM_GRO | S_IROTH;
const PERM_OWO: mode_t = PERM_GWO | S_IWOTH;

const GID_ROOT: u32 = AID_ROOT;
const GID_SYSTEM: u32 = AID_SYSTEM;
const GID_GRAPHICS: u32 = AID_GRAPHICS;
const GID_MEDIA_RW: u32 = AID_MEDIA_RW;

const FILE_ARR: &[BpfFileDesc] = &[
    BpfFileDesc {
        filename: "/etc/bpf/cputimeinstate/timeInState.bpf",
        prefix: "cputimeinstate/",
        critical: false,
        skip_on_user: false,
        maps: &[
            MapDesc::new(GID_SYSTEM, PERM_OWO, "cpu_last_pid_map"),
            MapDesc::new(GID_SYSTEM, PERM_OWO, "cpu_last_update_map"),
            MapDesc::new(GID_SYSTEM, PERM_OWO, "cpu_policy_map"),
            MapDesc::new(GID_SYSTEM, PERM_OWO, "freq_to_idx_map"),
            MapDesc::new(GID_SYSTEM, PERM_OWO, "nr_active_map"),
            MapDesc::new(GID_SYSTEM, PERM_OWO, "pid_task_aggregation_map"),
            MapDesc::new(GID_SYSTEM, PERM_ORO, "pid_time_in_state_map"),
            MapDesc::new(GID_SYSTEM, PERM_OWO, "pid_tracked_hash_map"),
            MapDesc::new(GID_SYSTEM, PERM_OWO, "pid_tracked_map"),
            MapDesc::new(GID_SYSTEM, PERM_OWO, "policy_freq_idx_map"),
            MapDesc::new(GID_SYSTEM, PERM_OWO, "policy_nr_active_map"),
            MapDesc::new(GID_SYSTEM, PERM_ORW, "total_time_in_state_map"),
            MapDesc::new(GID_SYSTEM, PERM_ORW, "uid_concurrent_times_map"),
            MapDesc::new(GID_SYSTEM, PERM_ORW, "uid_last_update_map"),
            MapDesc::new(GID_SYSTEM, PERM_ORW, "uid_time_in_state_map"),
        ],
        progs: &[
            ProgDesc::new(GID_SYSTEM, "tracepoint_power_cpu_frequency"),
            ProgDesc::new(GID_SYSTEM, "tracepoint_sched_sched_process_free"),
            ProgDesc::new(GID_SYSTEM, "tracepoint_sched_sched_switch"),
        ],
    },
    BpfFileDesc {
        filename: "/etc/bpf/fuseMedia.bpf",
        prefix: "",
        critical: false,
        skip_on_user: false,
        maps: &[],
        progs: &[ProgDesc::new(GID_MEDIA_RW, "fuse_media")],
    },
    BpfFileDesc {
        filename: "/etc/bpf/gpuMem.bpf",
        prefix: "",
        critical: false,
        skip_on_user: false,
        maps: &[MapDesc::new(GID_GRAPHICS, PERM_GRO, "gpu_mem_total_map")],
        progs: &[ProgDesc::new(GID_GRAPHICS, "tracepoint_gpu_mem_gpu_mem_total")],
    },
    BpfFileDesc {
        filename: "/etc/bpf/gpuWork.bpf",
        prefix: "",
        critical: false,
        skip_on_user: false,
        maps: &[
            MapDesc::new(GID_GRAPHICS, PERM_GRW, "gpu_work_map"),
            MapDesc::new(GID_GRAPHICS, PERM_GRW, "gpu_work_global_data"),
        ],
        progs: &[ProgDesc::new(GID_GRAPHICS, "tracepoint_power_gpu_work_period")],
    },
    BpfFileDesc {
        filename: "/etc/bpf/memevents/bpfMemEvents.bpf",
        prefix: "memevents/",
        critical: false,
        skip_on_user: false,
        maps: &[
            MapDesc::new_kver(GID_SYSTEM, PERM_GRW, KVER_5_10, "ams_rb"),
            MapDesc::new_kver(GID_SYSTEM, PERM_GRW, KVER_5_10, "lmkd_rb"),
        ],
        progs: &[
            ProgDesc::new_kver(GID_SYSTEM, KVER_5_10, "tracepoint_oom_mark_victim_ams"),
            ProgDesc::new_kver(
                GID_SYSTEM,
                KVER_5_10,
                "tracepoint_vmscan_mm_vmscan_direct_reclaim_begin_lmkd",
            ),
            ProgDesc::new_kver(
                GID_SYSTEM,
                KVER_5_10,
                "tracepoint_vmscan_mm_vmscan_direct_reclaim_end_lmkd",
            ),
            ProgDesc::new_kver(
                GID_SYSTEM,
                KVER_5_10,
                "tracepoint_vmscan_mm_vmscan_kswapd_wake_lmkd",
            ),
            ProgDesc::new_kver(
                GID_SYSTEM,
                KVER_5_10,
                "tracepoint_vmscan_mm_vmscan_kswapd_sleep_lmkd",
            ),
            ProgDesc::new_kver(
                GID_SYSTEM,
                KVER_6_1,
                "tracepoint_android_vendor_lmk_android_trigger_vendor_lmk_kill_lmkd",
            ),
            ProgDesc::new_kver(
                GID_SYSTEM,
                KVER_6_1,
                "tracepoint_kmem_mm_calculate_totalreserve_pages_lmkd",
            ),
        ],
    },
    BpfFileDesc {
        filename: "/etc/bpf/memevents/bpfMemEventsTest.bpf",
        prefix: "memevents/",
        critical: false,
        skip_on_user: true,
        maps: &[MapDesc::new_kver(GID_SYSTEM, PERM_GRW, KVER_5_10, "rb")],
        progs: &[
            ProgDesc::new_kver(GID_SYSTEM, KVER_5_10, "tracepoint_oom_mark_victim"),
            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_oom_kill"),
            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_direct_reclaim_begin"),
            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_direct_reclaim_end"),
            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_kswapd_wake"),
            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_kswapd_sleep"),
            ProgDesc::new_kver(GID_SYSTEM, KVER_6_1, "skfilter_android_trigger_vendor_lmk_kill"),
            ProgDesc::new_kver(GID_ROOT, KVER_6_1, "skfilter_calculate_totalreserve_pages"),
        ],
    },
    BpfFileDesc {
        filename: "/etc/bpf/bpfRingbufProg.bpf",
        prefix: "",
        critical: true,
        skip_on_user: true,
        maps: &[MapDesc::new_kver(GID_ROOT, PERM_GRW, KVER_5_10, "test_ringbuf")],
        progs: &[ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_ringbuf_test")],
    },
    BpfFileDesc {
        filename: "/vendor/etc/bpf/filterPowerSupplyEvents.bpf",
        prefix: "vendor/",
        critical: true,
        skip_on_user: false,
        maps: &[],
        progs: &[ProgDesc::new_kver(GID_SYSTEM, KVER_5_10, "skfilter_power_supply")],
    },
];

// TODO: Remove this code when fuse-bpf is upstreamed
fn set_fuse_prog_type(prog: OpenProgramMut) -> Result<(), anyhow::Error> {
    let path = Path::new("/sys/fs/fuse/bpf_prog_type_fuse");
    let prog_type_str =
        fs::read_to_string(path).map_err(|e| anyhow!("Failed to read fuse prog type: {e}"))?;
    let prog_type = prog_type_str
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow!("Failed to parse fuse prog type {prog_type_str}: {e}"))?;
    // SAFETY: If the return value is 0, program type should be updated correctly.
    // prog.set_prog_type can not be used because ProgramType does not contain BPF_PROG_TYPE_FUSE
    if unsafe { bpf_program__set_type(prog.as_libbpf_object().as_ptr(), prog_type) } != 0 {
        return Err(anyhow!("Failed to set fuse prog type {prog_type}"));
    }
    Ok(())
}

fn set_prog_types(open_file: &mut OpenObject) -> Result<(), anyhow::Error> {
    for mut prog in open_file.progs_mut() {
        let section_name =
            prog.section().to_str().ok_or_else(|| anyhow!("Failed to parse prog section name"))?;
        if section_name.starts_with("skfilter/") {
            prog.set_prog_type(ProgramType::SocketFilter);
        } else if section_name.starts_with("fuse/") {
            set_fuse_prog_type(prog)?;
        }
    }
    Ok(())
}

fn create_dir(dir_path: &Path) -> Result<(), anyhow::Error> {
    if dir_path.exists() {
        return Ok(());
    }
    fs::create_dir(dir_path)
        .map_err(|e| anyhow!("Failed to create {}: {e}", dir_path.display()))?;
    // The cast is not unnecessary on all platforms.
    #[allow(clippy::unnecessary_cast)]
    fs::set_permissions(
        dir_path,
        Permissions::from_mode((S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO) as u32),
    )
    .map_err(|e| anyhow!("Failed to set permissions for {}: {e}", dir_path.display()))?;
    Ok(())
}

fn leading_number(str: &str) -> u32 {
    let mut num_str = String::new();
    for c in str.chars() {
        if c.is_ascii_digit() {
            num_str.push(c);
        } else {
            break;
        }
    }
    num_str.parse().unwrap_or(0)
}

// Parses a kernel release string into a tuple of (major, minor, sub) version numbers.
// Examples:
// - "6.1.128-android14" returns (6, 1, 128)
// - "6.1.128android14" returns (6, 1, 128)
// - "6.1" returns (6, 1, 0)
fn parse_release(release: &str) -> (u32, u32, u32) {
    let mut iter = release.splitn(3, '.');
    let major = leading_number(iter.next().unwrap_or(""));
    let minor = leading_number(iter.next().unwrap_or(""));
    let sub = leading_number(iter.next().unwrap_or(""));
    (major, minor, sub)
}

fn kernel_version() -> Result<u32, anyhow::Error> {
    let mut buf: MaybeUninit<utsname> = MaybeUninit::zeroed();
    // SAFETY: If uname returns 0, the buf should be properly initialized.
    if unsafe { uname(buf.as_mut_ptr()) } != 0 {
        return Err(anyhow!("Failed to call uname system call."));
    }
    // SAFETY: `uname` returned 0, so the buf should be properly initialized.
    let buf = unsafe { buf.assume_init() };
    // SAFETY: buf.release is part of the utsname struct populated by uname.
    let release_cstr = unsafe { CStr::from_ptr(buf.release.as_ptr()) };
    let release = release_cstr
        .to_str()
        .map_err(|e| anyhow!("utsname release string is not valid UTF-8: {}", e))?;

    let (major, minor, sub) = parse_release(release);
    Ok(kver(major, minor, sub))
}

fn set_skip_loading(
    open_file: &mut OpenObject,
    file_desc: &BpfFileDesc,
) -> Result<(), anyhow::Error> {
    let kvers = kernel_version()?;

    for mut map in open_file.maps_mut() {
        let name =
            map.name().to_str().ok_or_else(|| anyhow!("Failed to parse map name into UTF-8"))?;
        for map_desc in file_desc.maps {
            if map_desc.name == name {
                if kvers < map_desc.min_kver || kvers >= map_desc.max_kver {
                    info!(
                        "skipping map {} min_kver:{:x} max_kver:{:x} kvers:{:x}",
                        name, map_desc.min_kver, map_desc.max_kver, kvers
                    );
                    map.set_autocreate(false)?;
                }
                break;
            }
        }
    }

    for mut prog in open_file.progs_mut() {
        let name =
            prog.name().to_str().ok_or_else(|| anyhow!("Failed to parse prog name into UTF-8"))?;
        for prog_desc in file_desc.progs {
            if prog_desc.name == name {
                if kvers < prog_desc.min_kver || kvers >= prog_desc.max_kver {
                    info!(
                        "skipping program {} min_kver:{:x} max_kver:{:x} kvers:{:x}",
                        name, prog_desc.min_kver, prog_desc.max_kver, kvers
                    );
                    prog.set_autoload(false);
                }
                break;
            }
        }
    }

    Ok(())
}

fn is_user_build() -> Result<bool, anyhow::Error> {
    if let Some(build_string) = system_properties::read("ro.build.type")? {
        Ok(build_string == "user")
    } else {
        Ok(false)
    }
}

fn libbpf_worker(file_desc: &BpfFileDesc) -> Result<(), anyhow::Error> {
    info!("Loading {}", file_desc.filename);
    if file_desc.skip_on_user && is_user_build()? {
        info!("Skip loading {} on user build", file_desc.filename);
        return Ok(());
    }
    let filepath = Path::new(file_desc.filename);
    // TODO: Make this error once the BPF loader migration completes.
    if !filepath.exists() {
        info!("Skipping load of {} as it does not exist", filepath.display());
        return Ok(());
    }
    let filename =
        filepath.file_stem().ok_or_else(|| anyhow!("Failed to parse stem from filename"))?;
    let filename = filename.to_str().ok_or_else(|| anyhow!("Failed to parse filename"))?;

    let mut ob = ObjectBuilder::default();
    let mut open_file = ob.open_file(filepath)?;
    // libbpf's open_file attempts to infer the prog type based on the section name. But, some
    // section names are not recognized, so the program type must be set explicitly for them.
    set_prog_types(&mut open_file)?;
    set_skip_loading(&mut open_file, file_desc)?;
    let mut loaded_file = open_file.load()?;

    let bpffs_path = "/sys/fs/bpf/".to_owned() + file_desc.prefix;
    create_dir(Path::new(&bpffs_path))?;

    for mut map in loaded_file.maps_mut() {
        let mut desc_found = false;
        let name =
            map.name().to_str().ok_or_else(|| anyhow!("Failed to parse map name into UTF-8"))?;
        let name = String::from(name);
        if name.ends_with(".rodata") {
            // Skip pinning map for .rodata section.
            continue;
        }
        for map_desc in file_desc.maps {
            if map_desc.name == name {
                desc_found = true;
                // SAFETY: bpf_map__autocreate just returns the field value of libbpf struct
                let autocreate = unsafe { bpf_map__autocreate(map.as_libbpf_object().as_ptr()) };
                if !autocreate {
                    // This map is not loaded
                    continue;
                }

                let pinpath_str = bpffs_path.clone() + "map_" + filename + "_" + &name;
                let pinpath = Path::new(&pinpath_str);
                debug!("Pinning: {}", pinpath.display());
                map.pin(pinpath).map_err(|e| anyhow!("Failed to pin map {name}: {e}"))?;
                fs::set_permissions(pinpath, Permissions::from_mode(map_desc.perms as _)).map_err(
                    |e| {
                        anyhow!(
                            "Failed to set permissions: {} on pinned map {}: {e}",
                            map_desc.perms,
                            pinpath.display()
                        )
                    },
                )?;
                chown(pinpath, Some(map_desc.owner), Some(map_desc.group)).map_err(|e| {
                    anyhow!(
                        "Failed to chown {} with owner: {} group: {} err: {e}",
                        pinpath.display(),
                        map_desc.owner,
                        map_desc.group
                    )
                })?;
                break;
            }
        }
        ensure!(desc_found, "Descriptor for {name} not found!");
    }

    for mut prog in loaded_file.progs_mut() {
        let mut desc_found = false;
        let name =
            prog.name().to_str().ok_or_else(|| anyhow!("Failed to parse prog name into UTF-8"))?;
        let name = String::from(name);
        for prog_desc in file_desc.progs {
            if prog_desc.name == name {
                desc_found = true;
                if !prog.autoload() {
                    // This program is not loaded
                    continue;
                }
                let pinpath_str = bpffs_path.clone() + "prog_" + filename + "_" + &name;
                let pinpath = Path::new(&pinpath_str);
                debug!("Pinning: {}", pinpath.display());
                prog.pin(pinpath).map_err(|e| anyhow!("Failed to pin prog {name}: {e}"))?;
                fs::set_permissions(pinpath, Permissions::from_mode(PERM_UGR as _)).map_err(
                    |e| {
                        anyhow!(
                            "Failed to set permissions on pinned prog {}: {e}",
                            pinpath.display()
                        )
                    },
                )?;
                chown(pinpath, Some(prog_desc.owner), Some(prog_desc.group)).map_err(|e| {
                    anyhow!(
                        "Failed to chown {} with owner: {} group: {} err: {e}",
                        pinpath.display(),
                        prog_desc.owner,
                        prog_desc.group
                    )
                })?;
                break;
            }
        }
        ensure!(desc_found, "Descriptor for {name} not found!");
    }
    Ok(())
}

fn load_libbpf_progs() {
    info!("Loading libbpf programs");
    for file_desc in FILE_ARR {
        if let Err(e) = libbpf_worker(file_desc) {
            if file_desc.critical {
                panic!("Error when loading {0}: {e}", file_desc.filename);
            } else {
                error!("Error when loading {0}: {e}", file_desc.filename);
            }
        };
    }
}

fn main() {
    let kmsg_fd = env::var("ANDROID_FILE__dev_kmsg").unwrap().parse::<i32>().unwrap();
    // SAFETY: The init script opens this file for us
    let kmsg_file = unsafe { File::from_raw_fd(kmsg_fd) };

    if let Err(logger) = BpfKmsgLogger::init(kmsg_file) {
        error!("BpfLoader-rs: log::setlogger failed: {}", logger);
    }

    // Redirect panic messages to both logcat and serial port
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    // Enable logging from libbpf
    set_print(Some((PrintLevel::Debug, libbpf_print)));

    load_libbpf_progs();
    info!("Loading legacy BPF progs");

    if let Err(e) = create_dir(Path::new("/sys/fs/bpf/vendor")) {
        panic!("Error during mkdir /sys/fs/bpf/vendor: {e}");
    };

    // SAFETY: Linking in the existing legacy vendor bpfloader functionality.
    // The following bindgen function can abort() or exit() on failure,
    // but will usually execve().
    unsafe {
        bpf_android_bindgen::vendorBpfLoader();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_parse_release() {
        assert_eq!(parse_release("6.1.128-android14-11-g213d628eb429-ab13297919"), (6, 1, 128));
        assert_eq!(parse_release("6.1.128_android14"), (6, 1, 128));
        assert_eq!(parse_release("6.1.128.4"), (6, 1, 128));
        assert_eq!(parse_release("6.1.android14"), (6, 1, 0));
        assert_eq!(parse_release("6.1-android14"), (6, 1, 0));
        assert_eq!(parse_release("6.1"), (6, 1, 0));
        assert_eq!(parse_release("6"), (6, 0, 0));
        assert_eq!(parse_release("android14"), (0, 0, 0));
    }
}
