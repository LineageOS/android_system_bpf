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
import urllib.request

from pathlib import Path

# Base URL for fetching artifacts from Android's continuous integration server.
BASE_URL = "https://ci.android.com/builds/submitted/{build_id}/{target}/latest/raw"

# A mapping from the target architecture to a more friendly name.
ARCH_MAP = {
    "kernel_aarch64": "arm64",
    "kernel_x86_64": "x86_64",
}

def parse_args():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bid",
        required=True,
        help="The build ID to download the vmlinux artifact from, e.g., 13748739.",
    )
    parser.add_argument(
        "--bug",
        required=True,
        action="append",
        help="The bug ID to include in the commit message. Can be specified multiple times.",
    )
    return parser.parse_args()

def get_kernel_version(build_id, target):
    """Determines the kernel version from the build's branch name."""
    url = os.path.join(BASE_URL.format(build_id=build_id, target=target), "BUILD_INFO")
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            branch = data.get("branch", "")
            # Example branch name: aosp_kernel-common-android13-5.15
            match = re.search(r"android\d+-(\d+\.\d+)", branch)
            if match:
                return match.group(1)
            else:
                raise ValueError(f"Could not determine kernel version from branch: {branch}")
    except (urllib.error.URLError, ValueError) as e:
        print(f"Error fetching or parsing BUILD_INFO for target {target}: {e}")
        return None

def download_vmlinux(build_id, target, kernel_version):
    """Downloads the vmlinux artifact for a given build ID, target, and kernel version."""
    arch = ARCH_MAP.get(target)
    if not arch:
        print(f"Unknown target: {target}")
        return

    dest_dir = Path(kernel_version) / arch
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / "vmlinux"

    print(f"Downloading vmlinux for {target} to {dest_file}...")
    command = [
        "/google/data/ro/projects/android/fetch_artifact",
        "--bid",
        build_id,
        "--target",
        target,
        "vmlinux",
        str(dest_file),
    ]
    try:
        subprocess.run(command, check=True)
        print(f"Successfully downloaded vmlinux for {target}.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error downloading vmlinux for {target}: {e}")

def main():
    """Main function."""
    args = parse_args()

    # We determine the kernel version from the aarch64 target,
    # assuming it will be the same for x86_64.
    kernel_version = get_kernel_version(args.bid, "kernel_aarch64")
    if not kernel_version:
        return

    for target in ARCH_MAP.keys():
        download_vmlinux(args.bid, target, kernel_version)

    try:
        print("Staging new vmlinux files (ignoring potential LFS errors)...")
        subprocess.run(["git", "add", kernel_version])  # check=True removed

        commit_message = f"Update {kernel_version} arm64 and x86_64 vmlinux to ab/{args.bid}"
        tag_lines = ["Test: treehugger"]
        if args.bug:
            tag_lines.extend([f"Bug: {b}" for b in args.bug])
        commit_message += "\n\n" + "\n".join(tag_lines)

        print(f"Committing with message: '{commit_message}'")
        subprocess.run(["git", "commit", "-s", "-m", commit_message], check=True)
        print("Successfully committed the changes.")
    except subprocess.CalledProcessError as e:
        print(f"Error during git operation: {e}")
    except FileNotFoundError:
        print("Error: 'git' command not found. Is git installed and in your PATH?")

if __name__ == "__main__":
    main()
