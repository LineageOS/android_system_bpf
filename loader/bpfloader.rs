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

// Enable dead_code until feature flag is removed.
#![cfg_attr(not(enable_libbpf), allow(dead_code))]

use android_ids::{AID_ROOT, AID_SYSTEM};
use android_logger::AndroidLogger;
use anyhow::{anyhow, ensure};
use libbpf_rs::{MapCore, ObjectBuilder};
use libc::{mode_t, S_IRGRP, S_IRUSR, S_IWGRP, S_IWUSR};
use log::{debug, error, info, Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
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

struct MapDesc {
    name: &'static str,
    perms: mode_t,
}

struct ProgDesc {
    name: &'static str,
}

struct BpfFileDesc {
    filename: &'static str,
    // Warning: setting this to 'true' will cause the system to boot loop if there are any issues
    // loading the bpf program.
    critical: bool,
    owner: u32,
    group: u32,
    maps: &'static [MapDesc],
    progs: &'static [ProgDesc],
}

const PERM_GRW: mode_t = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
const PERM_GRO: mode_t = S_IRUSR | S_IWUSR | S_IRGRP;
const PERM_GWO: mode_t = S_IRUSR | S_IWUSR | S_IWGRP;
const PERM_UGR: mode_t = S_IRUSR | S_IRGRP;

const FILE_ARR: &[BpfFileDesc] = &[BpfFileDesc {
    filename: "timeInState.bpf",
    critical: false,
    owner: AID_ROOT,
    group: AID_SYSTEM,
    maps: &[
        MapDesc { name: "cpu_last_pid_map", perms: PERM_GWO },
        MapDesc { name: "cpu_last_update_map", perms: PERM_GWO },
        MapDesc { name: "cpu_policy_map", perms: PERM_GWO },
        MapDesc { name: "freq_to_idx_map", perms: PERM_GWO },
        MapDesc { name: "nr_active_map", perms: PERM_GWO },
        MapDesc { name: "pid_task_aggregation_map", perms: PERM_GWO },
        MapDesc { name: "pid_time_in_state_map", perms: PERM_GRO },
        MapDesc { name: "pid_tracked_hash_map", perms: PERM_GWO },
        MapDesc { name: "pid_tracked_map", perms: PERM_GWO },
        MapDesc { name: "policy_freq_idx_map", perms: PERM_GWO },
        MapDesc { name: "policy_nr_active_map", perms: PERM_GWO },
        MapDesc { name: "total_time_in_state_map", perms: PERM_GRW },
        MapDesc { name: "uid_concurrent_times_map", perms: PERM_GRW },
        MapDesc { name: "uid_last_update_map", perms: PERM_GRW },
        MapDesc { name: "uid_time_in_state_map", perms: PERM_GRW },
    ],
    progs: &[
        ProgDesc { name: "tracepoint_power_cpu_frequency" },
        ProgDesc { name: "tracepoint_sched_sched_process_free" },
        ProgDesc { name: "tracepoint_sched_sched_switch" },
    ],
}];

fn libbpf_worker(file_desc: &BpfFileDesc) -> Result<(), anyhow::Error> {
    info!("Loading {}", file_desc.filename);
    let filepath = Path::new("/etc/bpf/").join(file_desc.filename);
    ensure!(filepath.exists(), "File not found {}", filepath.display());
    let filename =
        filepath.file_stem().ok_or_else(|| anyhow!("Failed to parse stem from filename"))?;
    let filename = filename.to_str().ok_or_else(|| anyhow!("Failed to parse filename"))?;

    let mut ob = ObjectBuilder::default();
    let open_file = ob.open_file(&filepath)?;
    let mut loaded_file = open_file.load()?;

    let bpffs_path = "/sys/fs/bpf/".to_owned();

    for mut map in loaded_file.maps_mut() {
        let mut desc_found = false;
        let name =
            map.name().to_str().ok_or_else(|| anyhow!("Failed to parse map name into UTF-8"))?;
        let name = String::from(name);
        for map_desc in file_desc.maps {
            if map_desc.name == name {
                desc_found = true;
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
                chown(pinpath, Some(file_desc.owner), Some(file_desc.group)).map_err(|e| {
                    anyhow!(
                        "Failed to chown {} with owner: {} group: {} err: {e}",
                        pinpath.display(),
                        file_desc.owner,
                        file_desc.group
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
                chown(pinpath, Some(file_desc.owner), Some(file_desc.group)).map_err(|e| {
                    anyhow!(
                        "Failed to chown {} with owner: {} group: {} err: {e}",
                        pinpath.display(),
                        file_desc.owner,
                        file_desc.group
                    )
                })?;
                break;
            }
        }
        ensure!(desc_found, "Descriptor for {name} not found!");
    }
    Ok(())
}

#[cfg(enable_libbpf)]
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

#[cfg(not(enable_libbpf))]
fn load_libbpf_progs() {
    // Empty stub for feature flag disabled case
    info!("Loading libbpf programs DISABLED");
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

    load_libbpf_progs();
    info!("Loading legacy BPF progs");

    // SAFETY: Linking in the existing legacy bpfloader functionality.
    // Any of the four following bindgen functions can abort() or exit()
    // on failure and execNetBpfLoadDone() execve()'s.
    unsafe {
        bpf_android_bindgen::initLogging();
        bpf_android_bindgen::createBpfFsSubDirectories();
        bpf_android_bindgen::legacyBpfLoader();
        bpf_android_bindgen::execNetBpfLoadDone();
    }
}
