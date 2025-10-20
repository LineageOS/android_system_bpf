# Vmlinux Headers for BPF

This directory contains pre-generated `vmlinux.h` headers for various kernel
versions and architectures. These headers are used by the Android build system
to compile BPF programs.

The headers are generated from `vmlinux` files downloaded from the Android
Continuous Integration build server. The large `vmlinux` files themselves are
not checked into the repository.

## Architecture Considerations on Android

A BPF program must be compiled with a vmlinux.h file that matches the
architecture of the target kernel.

*   **64-bit Systems**: On 64-bit Android systems (either `arm64` or `x86_64`),
    this is straightforward. The 64-bit userspace (where the application runs)
    matches the 64-bit kernel.
*   **32-bit Systems**: This is more complex on devices with a 32-bit Android
    userspace (`arm` or `x86`). At the time the BPF program is built, it's
    impossible to know if the device's kernel will be 32-bit or 64-bit. Because
    of this uncertainty, the system defaults to assuming a 32-bit userspace
    running on a 64-bit kernel. As a result, BPF programs that rely on libbpf
    will be disabled at runtime on systems that have a 32-bit kernel.

## Updating Existing vmlinux.h Files

To update the `vmlinux.h` files for an existing kernel version to a new build:

1.  Navigate to the `system/bpf/include/vmlinux` directory.
2.  Run the `update_vmlinux_h.py` script with the appropriate build ID and
    bug number(s):

    ```bash
        ./update_vmlinux_h.py --bid <BUILD_ID> --bug <BUG_ID> [--bug <ANOTHER_BUG_ID>]
    ```

The script will automatically:
- Build `bpftool` from your Android source tree.
- Download the `vmlinux` files for all architectures.
- Generate the `vmlinux.h` headers.
- Clean up the downloaded `vmlinux` files.
- Create a signed-off Git commit with the changes.

## Adding Support for a New Kernel Version

To add `vmlinux.h` headers for a new kernel version (e.g., `X.Y`):

1.  **Update the generation script:**
    - Open `update_vmlinux_h.py`.
    - Add the new version `X.Y` to the `SUPPORTED_VERSIONS` list.

2.  **Run the generation script:**
    - Follow the steps in the "Updating Existing vmlinux.h Files" section above.
    - This will download the new headers and create a commit.

3.  **Update the build configuration:**
    - Open `Android.bp`.
    - Add a new `cc_library_headers` module for the new kernel version `X.Y`,
      following the existing pattern:

      ```bp
      cc_library_headers {
          name: "vmlinux_h_X_Y",
          arch: {
              arm: {
                  export_include_dirs: ["X.Y/arm64"],
              },
              arm64: {
                  export_include_dirs: ["X.Y/arm64"],
              },
              x86: {
                  export_include_dirs: ["X.Y/x86_64"],
              },
              x86_64: {
                  export_include_dirs: ["X.Y/x86_64"],
              },
          },
      }
      ```

4.  **Amend the commit:**
    - Amend the commit created by the script to include the `Android.bp` changes.

    ```bash
    git add Android.bp
    git commit --amend --no-edit
    ```
