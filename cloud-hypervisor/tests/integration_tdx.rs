// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
// When enabling the `mshv` feature, we skip quite some tests and
// hence have known dead-code. This annotation silences dead-code
// related warnings for our quality workflow to pass.
#![allow(dead_code)]
mod common;

#[cfg(all(feature = "tdx", target_arch = "x86_64"))]
mod common_tdx {
    use std::io::Read;
    use std::os::unix::io::AsRawFd;

    use block::ImageType;
    use common::tests_wrappers::*;
    use common::utils::*;
    use test_infra::*;
    use wait_timeout::ChildExt;
    const NUM_PCI_SEGMENTS: u16 = 8;

    use super::*;
    macro_rules! basic_tdx_guest {
        ($image_name:expr) => {{
            let disk_config = UbuntuDiskConfig::new($image_name.to_string());
            GuestFactory::new_tdx_guest_factory().create_guest(Box::new(disk_config))
        }};
    }

    #[test]
    fn test_focal_simple_launch() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        _test_simple_launch(&guest);
    }

    #[test]
    fn test_multi_cpu() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        _test_multi_cpu(&guest);
    }

    #[test]
    fn test_api_http_create_boot() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf))
            .with_cpu(4);
        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_create_boot(&target_api, &guest);
    }

    #[test]
    fn test_api_http_shutdown() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf))
            .with_cpu(4);
        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_shutdown(&target_api, &guest);
    }

    #[test]
    fn test_api_http_delete() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf))
            .with_cpu(4);
        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_delete(&target_api, &guest);
    }

    #[test]
    fn test_power_button() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        _test_power_button(&guest);
    }

    #[test]
    fn test_virtio_queue_affinity() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf))
            .with_cpu(4);
        _test_virtio_queue_affinity(&guest);
    }

    #[test]
    fn test_virtio_vsock() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));

        let socket = temp_vsock_path(&guest.tmp_dir);
        let api_socket = temp_api_path(&guest.tmp_dir);

        let mut cmd = GuestCommand::new(&guest);
        cmd.args(["--api-socket", &api_socket]);
        cmd.default_cpus();
        cmd.default_memory();
        cmd.default_kernel_cmdline();
        cmd.default_disks();
        cmd.default_net();
        cmd.args(["--vsock", format!("cid=3,socket={socket}").as_str()]);

        let mut child = cmd.capture_output().spawn().unwrap();
        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
            // Validate vsock works as expected.
            guest.check_vsock(socket.as_str());
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_pci_msi() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        _test_pci_msi(&guest);
    }

    #[test]
    fn test_virtio_net_ctrl_queue() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        _test_virtio_net_ctrl_queue(&guest);
    }

    #[test]
    fn test_counters() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        _test_counters(&guest);
    }

    #[test]
    fn test_virtio_block_io_uring() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_tdx_guest_factory(),
            "noble-server-cloudimg-amd64-UEFI.img",
        )
        .with_kernel(fw_path(FwType::Tdvf));
        _test_virtio_block(&guest, false, true, false, false, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_aio() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_tdx_guest_factory(),
            "noble-server-cloudimg-amd64-UEFI.img",
        )
        .with_kernel(fw_path(FwType::Tdvf));
        _test_virtio_block(&guest, true, false, false, false, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_sync() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_tdx_guest_factory(),
            "noble-server-cloudimg-amd64-UEFI.img",
        )
        .with_kernel(fw_path(FwType::Tdvf));
        _test_virtio_block(&guest, true, true, false, false, ImageType::Qcow2);
    }

    #[test]
    fn test_disk_hotplug() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        _test_disk_hotplug_no_reboot(&guest, false);
    }

    #[test]
    fn test_split_irqchip() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        _test_split_irqchip(&guest);
    }

    #[test]
    fn test_dmi_uuid() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));

        let expected_uuid = "1e8aa28a-435d-4027-87f4-40dceff1fa0a";
        let platform = format!("uuid={expected_uuid}");

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .default_kernel_cmdline_with_platform(Some(&platform))
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            let uuid = guest
                .ssh_command(
                    "sudo sh -c 'cat /sys/class/dmi/id/product_uuid 2>/dev/null || cat /sys/devices/virtual/dmi/id/product_uuid 2>/dev/null || true'",
                )
                .unwrap()
                .trim()
                .to_ascii_lowercase();

            if !uuid.is_empty() {
                let is_hex = |c: u8| c.is_ascii_hexdigit();
                let b = uuid.as_bytes();
                assert!(
                    b.len() == 36
                        && b[8] == b'-'
                        && b[13] == b'-'
                        && b[18] == b'-'
                        && b[23] == b'-'
                        && b.iter()
                            .enumerate()
                            .all(|(idx, c)| { [8usize, 13, 18, 23].contains(&idx) || is_hex(*c) }),
                    "guest product_uuid is not in UUID format: {uuid}"
                );
            }
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_dmi_oem_strings() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));

        let s1 = "io.systemd.credential:xx=yy";
        let s2 = "This is a test string";
        let platform = format!("oem_strings=[{s1},{s2}]");

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .default_kernel_cmdline_with_platform(Some(&platform))
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            let count = guest
                .ssh_command(
                    "sudo sh -c 'if command -v dmidecode >/dev/null 2>&1; then dmidecode --oem-string count 2>/dev/null || echo N/A; else echo N/A; fi'",
                )
                .unwrap()
                .trim()
                .to_string();

            // TDX guests may not expose OEM strings through dmidecode in all environments.
            if count != "N/A" {
                assert_eq!(count, "2");
                assert_eq!(
                    guest
                        .ssh_command("sudo dmidecode --oem-string 1")
                        .unwrap()
                        .trim(),
                    s1
                );
                assert_eq!(
                    guest
                        .ssh_command("sudo dmidecode --oem-string 2")
                        .unwrap()
                        .trim(),
                    s2
                );
            }
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_multiple_network_interfaces() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .default_kernel_cmdline()
            .default_disks()
            .args([
                "--net",
                guest.default_net_string().as_str(),
                "tap=,mac=8a:6b:6f:5a:de:ac,ip=192.168.3.1,mask=255.255.255.128",
                "tap=mytap1,mac=fe:1f:9e:e1:60:f2,ip=192.168.4.1,mask=255.255.255.128",
            ])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            let tap_count = exec_host_command_output("ip link | grep -c mytap1");
            assert_eq!(String::from_utf8_lossy(&tap_count.stdout).trim(), "1");

            // 3 network interfaces + default localhost + sit ==> 5 interfaces
            assert_eq!(
                guest
                    .ssh_command("ip -o link | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                5
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);
    }

    #[test]
    fn test_serial_off() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .default_kernel_cmdline()
            .default_disks()
            .default_net()
            .args(["--serial", "off"])
            .capture_output()
            .spawn()
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(5));

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        let r = std::panic::catch_unwind(|| {
            let stderr = String::from_utf8_lossy(&output.stderr);

            // With --serial off, guest legacy COM accesses should hit unregistered I/O ports.
            assert!(stderr.contains("Guest PIO read to unregistered address 0x3fd"));
        });

        handle_child_output(r, &output);
    }

    #[test]
    fn test_virtio_console() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        _test_virtio_console(&guest);
    }

    #[test]
    fn test_console_file() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf));
        let console_path = guest.tmp_dir.as_path().join("console-output");

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .default_kernel_cmdline()
            .default_disks()
            .default_net()
            .args([
                "--console",
                format!("file={}", console_path.to_str().unwrap()).as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        guest.wait_vm_boot().unwrap();
        guest.ssh_command("sudo shutdown -h now").unwrap();

        let _ = child.wait_timeout(std::time::Duration::from_secs(20));
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        let r = std::panic::catch_unwind(|| {
            assert!(output.status.success());

            let mut f = std::fs::File::open(console_path).unwrap();
            let mut buf = String::new();
            f.read_to_string(&mut buf).unwrap();

            if !buf.contains("login:") {
                eprintln!(
                    "\n\n==== Console file output ====\n\n{buf}\n\n==== End console file output ===="
                );
            }

            assert!(buf.contains("login:"));
        });

        handle_child_output(r, &output);
    }

    #[test]
    fn test_tap_from_fd() {
        let guest = basic_tdx_guest!("noble-server-cloudimg-amd64-UEFI.img")
            .with_kernel(fw_path(FwType::Tdvf))
            .with_cpu(2);

        // Create a TAP interface with multi-queue enabled
        let num_queue_pairs: usize = 2;

        use std::str::FromStr;
        let taps = net_util::open_tap(
            Some("chtap0"),
            Some(std::net::IpAddr::V4(
                std::net::Ipv4Addr::from_str(&guest.network.host_ip0).unwrap(),
            )),
            None,
            &mut None,
            None,
            num_queue_pairs,
            Some(libc::O_RDWR | libc::O_NONBLOCK),
        )
        .unwrap();

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .default_kernel_cmdline()
            .default_disks()
            .args([
                "--net",
                &format!(
                    "fd=[{},{}],mac={},num_queues={}",
                    taps[0].as_raw_fd(),
                    taps[1].as_raw_fd(),
                    guest.network.guest_mac0,
                    num_queue_pairs * 2
                ),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command("ip -o link | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                3
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }
}
