#!/usr/bin/env python3
#
# Copyright (C) 2025 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

# Base URL for fetching artifacts from Android's continuous integration server.
BASE_URL = "https://ci.android.com/builds/submitted/{build_id}/{target}/latest/raw"

# A mapping from the target architecture to a more friendly name.
ARCH_MAP = {
    "kernel_aarch64": "arm64",
    "kernel_x86_64": "x86_64",
}

# Kernel versions for which we need to create placeholder files.
SUPPORTED_VERSIONS = ["6.12", "6.6", "6.1", "5.15", "5.10"]

def spinner_animation(stop_event):
    """Displays a spinner animation in the console."""
    spinner_chars = "|/-\\"
    while not stop_event.is_set():
        for char in spinner_chars:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b')

def parse_args():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Build bpftool, download vmlinux, generate vmlinux.h, "
                    "and commit.")
    parser.add_argument(
        "--bid",
        required=True,
        help="The build ID to download the vmlinux artifacts from.",
    )
    parser.add_argument(
        "--bug",
        required=True,
        action="append",
        help="The bug ID to include in the commit message. Can be specified "
             "multiple times.",
    )
    return parser.parse_args()

def get_android_build_top():
    """Determines the Android root directory relative to the script's location."""
    script_dir = Path(__file__).parent.resolve()
    android_top = script_dir.parents[3]
    if not (android_top / "build").is_dir():
        print(f"Error: Could not find Android root at {android_top}")
        return None
    return android_top

def create_placeholders(vmlinux_dir):
    """Creates empty placeholder vmlinux.h files to satisfy the build system."""
    print("Creating placeholder vmlinux.h files if they don't exist...")
    for version in SUPPORTED_VERSIONS:
        for arch in ARCH_MAP.values():
            placeholder_dir = vmlinux_dir / version / arch
            placeholder_dir.mkdir(parents=True, exist_ok=True)
            (placeholder_dir / "vmlinux.h").touch()

def build_bpftool(android_top):
    """Builds the bpftool host utility with a spinner."""
    print("Building bpftool... ", end="")
    build_command = [
        "build/soong/soong_ui.bash",
        "--make-mode",
        "TARGET_PRODUCT=aosp_cf_x86_64_phone",
        "TARGET_RELEASE=trunk",
        "TARGET_BUILD_VARIANT=userdebug",
        "HOST_OS=linux",
        "bpftool",
    ]

    stop_spinner = threading.Event()
    spinner_thread = threading.Thread(target=spinner_animation,
                                      args=(stop_spinner,))
    spinner_thread.start()

    try:
        result = subprocess.run(build_command, cwd=android_top,
                                capture_output=True, text=True)
        stop_spinner.set()
        spinner_thread.join()

        if result.returncode != 0:
            sys.stdout.write("\b \b")  # Erase final spinner char
            print("\nError: bpftool build failed.")
            print(result.stderr)
            return None

        bpftool_path = android_top / "out/host/linux-x86/bin/bpftool"
        if not bpftool_path.is_file():
            print("\nError: bpftool build succeeded but the binary was not "
                  "found.")
            return None

        sys.stdout.write("\b \b")  # Erase final spinner char
        print("Done.")
        return bpftool_path
    except Exception as e:
        stop_spinner.set()
        spinner_thread.join()
        sys.stdout.write("\b \b")
        print(f"\nAn unexpected error occurred during build: {e}")
        return None

def get_kernel_version(build_id, target):
    """Determines the kernel version from the build's branch name."""
    url = BASE_URL.format(build_id=build_id, target=target) + "/BUILD_INFO"
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            branch = data.get("branch", "")
            match = re.search(r"android\d+-(\d+\.\d+)", branch)
            if match:
                return match.group(1)
            raise ValueError("Could not determine kernel version from branch: "
                             f"{branch}")
    except (urllib.error.URLError, ValueError) as e:
        print(f"Error fetching or parsing BUILD_INFO for {target}: {e}")
        return None

def download_vmlinux(build_id, target, dest_file):
    """Downloads a vmlinux artifact from the build server."""
    print(f"Downloading vmlinux for {target} to {dest_file}...")
    fetch_command = [
        "/google/data/ro/projects/android/fetch_artifact",
        "--bid", build_id, "--target", target, "vmlinux", str(dest_file)
    ]
    try:
        subprocess.run(fetch_command, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error downloading vmlinux for {target}: {e}")
        return False

def generate_header(bpftool_path, vmlinux_file, header_file):
    """Generates a vmlinux.h header from a vmlinux file."""
    print(f"Generating {header_file}...")
    bpftool_command = [
        bpftool_path, "btf", "dump", "file", str(vmlinux_file), "format", "c"
    ]
    try:
        with open(header_file, "w") as f:
            subprocess.run(bpftool_command, check=True, stdout=f)
        print(f"Successfully generated {header_file}.")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error generating header from {vmlinux_file}: {e}")
        return False

def main():
    """Main script execution."""
    args = parse_args()
    android_top = get_android_build_top()
    if not android_top:
        return 1

    os.chdir(Path(__file__).parent.resolve())
    create_placeholders(Path.cwd())

    bpftool_path = build_bpftool(android_top)
    if not bpftool_path:
        return 1

    kernel_version = get_kernel_version(args.bid, "kernel_aarch64")
    if not kernel_version:
        return 1

    updated_archs = []
    for target, arch in ARCH_MAP.items():
        dest_dir = Path(kernel_version) / arch
        dest_dir.mkdir(parents=True, exist_ok=True)
        vmlinux_file = dest_dir / "vmlinux"
        header_file = dest_dir / "vmlinux.h"

        if not download_vmlinux(args.bid, target, vmlinux_file):
            continue

        if generate_header(bpftool_path, vmlinux_file, header_file):
            updated_archs.append(arch)

        if vmlinux_file.exists():
            print(f"Cleaning up {vmlinux_file}...")
            vmlinux_file.unlink()

    if len(updated_archs) != len(ARCH_MAP):
        print("Error: Failed to generate headers for all architectures. "
              "Aborting commit.")
        return 1

    try:
        print("Staging new vmlinux.h files...")
        subprocess.run(["git", "add", kernel_version], check=True)

        arch_string = " and ".join(sorted(updated_archs))
        commit_message = (
            f"Update {kernel_version} {arch_string} vmlinux.h to "
            f"ab/{args.bid}"
        )
        tag_lines = ["Test: treehugger"]
        tag_lines.extend([f"Bug: {b}" for b in args.bug])
        commit_message += "\n\n" + "\n".join(tag_lines)

        print("Committing changes...")
        subprocess.run(["git", "commit", "-s", "-m", commit_message],
                       check=True)
        print("Successfully committed the changes.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error during git operation: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
