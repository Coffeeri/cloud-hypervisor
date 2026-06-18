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

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub struct KvmTdxExit {
    pub type_: u32,
    pub pad: u32,
    pub u: KvmTdxExitU,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union KvmTdxExitU {
    pub vmcall: KvmTdxExitVmcall,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct KvmTdxExitVmcall {
    pub type_: u64,
    pub subfunction: u64,
    pub reg_mask: u64,
    pub in_r12: u64,
    pub in_r13: u64,
    pub in_r14: u64,
    pub in_r15: u64,
    pub in_rbx: u64,
    pub in_rdi: u64,
    pub in_rsi: u64,
    pub in_r8: u64,
    pub in_r9: u64,
    pub in_rdx: u64,
    pub status_code: u64,
    pub out_r11: u64,
    pub out_r12: u64,
    pub out_r13: u64,
    pub out_r14: u64,
    pub out_r15: u64,
    pub out_rbx: u64,
    pub out_rdi: u64,
    pub out_rsi: u64,
    pub out_r8: u64,
    pub out_r9: u64,
    pub out_rdx: u64,
}

// Compile-time ABI guards: keep these Rust struct layouts aligned with
// the corresponding KVM/TDX kernel definitions.
const _: () = assert!(size_of::<KvmTdxCmd>() == 24);
const _: () = assert!(size_of::<KvmTdxInitMemRegion>() == 24);
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
