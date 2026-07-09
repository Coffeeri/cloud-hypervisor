use std::mem::size_of;

use kvm_bindings;

#[repr(u32)]
pub(crate) enum TdxCommand {
    Capabilities = 0,
    InitVm,
    InitVcpu,
    InitMemRegion,
    Finalize,
}

pub enum TdxExitDetails {
    GetQuote { gpa: u64, size: u64 },
    SetupEventNotifyInterrupt { vector: u8 },
}

pub enum TdxExitStatus {
    Success,
    InvalidOperand,
}

pub(crate) const TDX_MAX_NR_CPUID_CONFIGS: usize = 80;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug)]
pub struct kvm_cpuid2 {
    pub nent: u32,
    pub padding: u32,
    pub entries: [kvm_bindings::kvm_cpuid_entry2; TDX_MAX_NR_CPUID_CONFIGS],
}

impl Default for kvm_cpuid2 {
    fn default() -> Self {
        Self {
            nent: TDX_MAX_NR_CPUID_CONFIGS as u32,
            padding: 0,
            entries: [kvm_bindings::kvm_cpuid_entry2::default(); TDX_MAX_NR_CPUID_CONFIGS],
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct kvm_tdx_capabilities {
    pub supported_attrs: u64,
    pub supported_xfam: u64,
    pub kernel_tdvmcallinfo_1_r11: u64,
    pub user_tdvmcallinfo_1_r11: u64,
    pub kernel_tdvmcallinfo_1_r12: u64,
    pub user_tdvmcallinfo_1_r12: u64,
    pub reserved: [u64; 250],
    pub cpuid: kvm_cpuid2,
}

impl Default for kvm_tdx_capabilities {
    fn default() -> Self {
        Self {
            supported_attrs: 0,
            supported_xfam: 0,
            kernel_tdvmcallinfo_1_r11: 0,
            user_tdvmcallinfo_1_r11: 0,
            kernel_tdvmcallinfo_1_r12: 0,
            user_tdvmcallinfo_1_r12: 0,
            reserved: [0_u64; 250],
            cpuid: kvm_cpuid2::default(),
        }
    }
}

#[repr(C)]
pub(crate) struct KvmTdxCmd {
    pub id: TdxCommand,
    pub flags: u32,
    pub data: u64,
    pub hw_error: u64,
}

#[repr(C)]
#[derive(Debug)]
pub(crate) struct KvmTdxInitVm {
    pub attributes: u64,
    pub xfam: u64,
    pub mrconfigid: [u64; 6],
    pub mrowner: [u64; 6],
    pub mrownerconfig: [u64; 6],
    pub reserved: [u64; 12],
    pub cpuid: kvm_cpuid2,
}

#[repr(C)]
#[derive(Debug)]
pub(crate) struct KvmTdxInitMemRegion {
    pub source_addr: u64,
    pub gpa: u64,
    pub nr_pages: u64,
}

// Layout of `struct { __u64 flags; __u64 nr; union { ... }; } tdx;` within the
// `KVM_EXIT_TDX` arm of the top-level `kvm_run` union, as defined by the
// running kernel's `include/uapi/linux/kvm.h`. Note this differs from older
// (pre-upstream) KVM/TDX ABI proposals that used a generic `vmcall` struct
// with `subfunction`/`in_r12..in_rdx`/`status_code`/`out_r11..out_rdx`
// fields; that layout is *not* what current upstream kernels expose.
#[allow(dead_code)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct KvmTdxExit {
    pub flags: u64,
    /// TDVMCALL subfunction/leaf number (e.g. `TDG_VP_VMCALL_GET_QUOTE`).
    pub nr: u64,
    pub u: KvmTdxExitU,
}

// `ret` is always the first `u64` of every variant below, so it aliases the
// same offset (16 bytes into `KvmTdxExit`) regardless of which variant is
// active. This lets `set_tdx_status()` write the TDVMCALL return status
// through any variant without needing to know which one KVM populated.
#[repr(C)]
#[derive(Copy, Clone)]
pub union KvmTdxExitU {
    pub unknown: KvmTdxExitUnknown,
    pub get_quote: KvmTdxExitGetQuote,
    pub get_tdvmcall_info: KvmTdxExitGetTdVmCallInfo,
    pub setup_event_notify: KvmTdxExitSetupEventNotify,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmTdxExitUnknown {
    pub ret: u64,
    pub data: [u64; 5],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmTdxExitGetQuote {
    pub ret: u64,
    pub gpa: u64,
    pub size: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmTdxExitGetTdVmCallInfo {
    pub ret: u64,
    pub leaf: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmTdxExitSetupEventNotify {
    pub ret: u64,
    pub vector: u64,
}

// Compile-time ABI guards: keep these Rust struct layouts aligned with
// the corresponding KVM/TDX kernel definitions.
const _: () = assert!(size_of::<KvmTdxCmd>() == 24);
const _: () = assert!(size_of::<KvmTdxInitMemRegion>() == 24);
const _: () = assert!(size_of::<KvmTdxExitUnknown>() == 48);
const _: () = assert!(size_of::<KvmTdxExitGetQuote>() == 24);
const _: () = assert!(size_of::<KvmTdxExitGetTdVmCallInfo>() == 48);
const _: () = assert!(size_of::<KvmTdxExitSetupEventNotify>() == 16);
const _: () = assert!(size_of::<KvmTdxExit>() == 64);
const _: () = assert!(
    size_of::<kvm_cpuid2>()
        == size_of::<u32>() * 2
            + size_of::<kvm_bindings::kvm_cpuid_entry2>() * TDX_MAX_NR_CPUID_CONFIGS
);
const _: () =
    assert!(size_of::<kvm_tdx_capabilities>() == size_of::<u64>() * 256 + size_of::<kvm_cpuid2>());
const _: () = assert!(
    size_of::<KvmTdxInitVm>() == size_of::<u64>() * (2 + 6 + 6 + 6 + 12) + size_of::<kvm_cpuid2>()
);
