# Intel TDX

Intel® Trust Domain Extensions (Intel® TDX) is an Intel technology designed to
isolate virtual machines from the VMM, hypervisor and any other software on the
host platform. Here are some useful links:

- [TDX Homepage](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html):
  more information about TDX technical aspects, design and specification

- [Linux kernel](https://github.com/torvalds/linux) (version >= v6.17.0):
  includes the required TDX changes for both the host and guest sides. The
  host kernel must be compiled with `CONFIG_INTEL_TDX_HOST=y` and
  `CONFIG_KVM_INTEL_TDX=y`, while the guest kernel must be compiled with
  `CONFIG_TDX_GUEST_DRIVER=y` and `CONFIG_INTEL_TDX_GUEST=y`

- [EDK2 project](https://github.com/tianocore/edk2): the TDVF firmware

- [Confidential Containers project](https://github.com/confidential-containers/td-shim):
  the TDShim firmware

## Cloud Hypervisor support

It is required to use a machine with TDX enabled in hardware and
with the host OS compiled from the [Linux kernel](https://github.com/torvalds/linux) (version >= v6.17.0).
The host environment can also be setup with the [TDX Linux](https://github.com/intel/tdx-linux).

Cloud Hypervisor can run TDX VM (Trust Domain) by loading a TD firmware ([TDVF](https://github.com/tianocore/edk2)),
which will then load the guest kernel from the image. The image must be custom
as it must include a kernel built from the [Linux kernel](https://github.com/torvalds/linux) (version >= v6.17.0).
Cloud Hypervisor can also boot a TDX VM with direct kernel boot using [TDshim](https://github.com/confidential-containers/td-shim).
The custom Linux kernel for the guest can be built with the [TDX Linux](https://github.com/intel/tdx-linux).

### TDVF

> **Note**
> The latest version of TDVF being tested is [edk2-stable202602](https://github.com/tianocore/edk2/releases/tag/edk2-stable202602).

The firmware can be built as follows:

```bash
sudo apt-get update
sudo apt-get install uuid-dev nasm iasl build-essential python3-distutils git

git clone https://github.com/tianocore/edk2.git
cd edk2
git checkout edk2-stable202602
source ./edksetup.sh
git submodule update --init --recursive
make -C BaseTools -j `nproc`
build -p OvmfPkg/IntelTdx/IntelTdxX64.dsc -a X64 -t GCC5 -b RELEASE
```

If debug logs are needed, here is the alternative command:

```bash
build -p OvmfPkg/IntelTdx/IntelTdxX64.dsc -a X64 -t GCC5 -D DEBUG_ON_SERIAL_PORT=TRUE
```

On the Cloud Hypervisor side, all you need is to build the project with the
`tdx` feature enabled:

```bash
cargo build --features tdx
```

And run a TDX VM by providing the firmware previously built, along with the
guest image containing the TDX enlightened kernel.

```bash
./cloud-hypervisor \
    --platform tdx=on \
    --firmware edk2/Build/IntelTdx/RELEASE_GCC5/FV/OVMF.fd \
    --cpus boot=1,max_phys_bits=52 \
    --memory size=1G \
    --serial tty \
    --console off \
    --disk path=tdx_guest_img
```

And here is the alternative command when looking for debug logs from the
firmware:

```bash
./cloud-hypervisor \
    --platform tdx=on \
    --firmware edk2/Build/IntelTdx/DEBUG_GCC5/FV/OVMF.fd \
    --cpus boot=1,max_phys_bits=52 \
    --memory size=1G \
    --disk path=tdx_guest_img \
    --serial tty \
    --console off
```

### TDShim

> **Note**
> The latest version of TDShim being tested is [a471f1ccc64f39aff428344d9365ec094258728a](https://github.com/confidential-containers/td-shim/commit/a471f1ccc64f39aff428344d9365ec094258728a).

This is a lightweight version of the TDVF, written in Rust and designed for
direct kernel boot, which is useful for containers use cases.

To build TDShim from source, it is required to install `Rust`, `NASM`,
and `LLVM` first. The TDshim can be built as follows:

```bash
git clone https://github.com/confidential-containers/td-shim
cd td-shim
git checkout a471f1ccc64f39aff428344d9365ec094258728a

export CC=clang
export AR=llvm-ar
export CC_x86_64_unknown_none=clang
export AR_x86_64_unknown_none=llvm-ar

git submodule update --init --recursive
./sh_script/preparation.sh

cargo build -p td-shim --target x86_64-unknown-none --release --features=main,tdx --no-default-features
cargo run -p td-shim-tools --bin td-shim-ld --features=linker -- target/x86_64-unknown-none/release/ResetVector.bin target/x86_64-unknown-none/release/td-shim -o target/release/final.bin
```

If debug logs from the TDShim is needed, here are the alternative
commands:

```bash
cargo build -p td-shim --target x86_64-unknown-none --profile dev-opt --features=main,tdx,lazy-accept --no-default-features
cargo run -p td-shim-tools --bin td-shim-ld --features=linker -- target/x86_64-unknown-none/dev-opt/ResetVector.bin target/x86_64-unknown-none/dev-opt/td-shim -o target/debug/final.bin
```

And run a TDX VM by providing the firmware previously built, along with a guest
kernel built from the [Linux kernel](https://github.com/torvalds/linux) (version >= v6.17.0)
or the [TDX Linux](https://github.com/intel/tdx-linux).
The appropriate kernel boot options must be provided through the `--cmdline`
option as well.

```bash
./cloud-hypervisor \
    --platform tdx=on \
    --firmware td-shim/target/release/final.bin \
    --kernel bzImage \
    --cmdline "root=/dev/vda1 rw console=ttyS0 ignore_loglevel earlyprintk=ttyS0" \
    --cpus boot=1,max_phys_bits=52  \
    --memory size=1G \
    --disk path=tdx_guest_img
```

And here is the alternative command when looking for debug logs from the
TDShim:

```bash
./cloud-hypervisor \
    --platform tdx=on \
    --firmware td-shim/target/debug/final.bin \
    --kernel bzImage \
    --cmdline "root=/dev/vda1 rw console=ttyS0 ignore_loglevel earlyprintk=ttyS0" \
    --cpus boot=1,max_phys_bits=52  \
    --memory size=1G \
    --disk path=tdx_guest_img
```

### Guest kernel limitations

#### PCI hotplug through ACPI

Unless you run the guest kernel with the parameter `tdx_disable_filter`, ACPI
devices responsible for handling PCI hotplug (PCI hotplug controller, PCI
Express Bus and Generic Event Device) will not be allowed, therefore the
corresponding drivers will not be loaded and the PCI hotplug feature will not
be supported.
