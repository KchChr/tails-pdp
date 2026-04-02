use core::ptr::addr_of;

use aya_ebpf::{helpers::bpf_probe_read_kernel, programs::LsmContext};
use tails_pdp_common::{SOCKET_IP_LEN, SocketFamily, SocketTransport};

use crate::vmlinux;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const SOCK_STREAM: i16 = 1;
const SOCK_DGRAM: i16 = 2;

#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[derive(Copy, Clone)]
pub(crate) struct ResourceIdentity {
    pub file_device: u64,
    pub file_inode: u64,
    pub socket_family: SocketFamily,
    pub socket_transport: SocketTransport,
    pub socket_port: u16,
    pub socket_ip: [u8; SOCKET_IP_LEN],
}

impl ResourceIdentity {
    pub const fn empty() -> Self {
        Self {
            file_device: 0,
            file_inode: 0,
            socket_family: SocketFamily::Any,
            socket_transport: SocketTransport::Any,
            socket_port: 0,
            socket_ip: [0; SOCKET_IP_LEN],
        }
    }

    pub const fn from_file(device: u64, inode: u64) -> Self {
        Self {
            file_device: device,
            file_inode: inode,
            socket_family: SocketFamily::Any,
            socket_transport: SocketTransport::Any,
            socket_port: 0,
            socket_ip: [0; SOCKET_IP_LEN],
        }
    }
}

fn ntohs(value: u16) -> u16 {
    value.swap_bytes()
}

fn read_socket_transport(socket_ptr: *const vmlinux::socket) -> SocketTransport {
    if socket_ptr.is_null() {
        return SocketTransport::Any;
    }

    let Ok(socket_type) = (unsafe { bpf_probe_read_kernel(addr_of!((*socket_ptr).type_)) }) else {
        return SocketTransport::Any;
    };

    match socket_type {
        SOCK_STREAM => SocketTransport::Tcp,
        SOCK_DGRAM => SocketTransport::Udp,
        _ => SocketTransport::Any,
    }
}

pub(crate) fn read_file_open_resource_identity(ctx: &LsmContext) -> ResourceIdentity {
    let file_ptr: *const vmlinux::file = ctx.arg(0);
    if file_ptr.is_null() {
        return ResourceIdentity::empty();
    }

    let Ok(inode_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*file_ptr).f_inode)) }) else {
        return ResourceIdentity::empty();
    };
    if inode_ptr.is_null() {
        return ResourceIdentity::empty();
    }

    let Ok(sb_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*inode_ptr).i_sb)) }) else {
        return ResourceIdentity::empty();
    };
    if sb_ptr.is_null() {
        return ResourceIdentity::empty();
    }

    let Ok(device) = (unsafe { bpf_probe_read_kernel(addr_of!((*sb_ptr).s_dev)) }) else {
        return ResourceIdentity::empty();
    };
    let Ok(inode) = (unsafe { bpf_probe_read_kernel(addr_of!((*inode_ptr).i_ino)) }) else {
        return ResourceIdentity::empty();
    };

    ResourceIdentity::from_file(device as u64, inode)
}

pub(crate) fn read_socket_bind_resource_identity(ctx: &LsmContext) -> ResourceIdentity {
    let socket_ptr: *const vmlinux::socket = ctx.arg(0);
    let address_ptr: *const vmlinux::sockaddr = ctx.arg(1);
    if address_ptr.is_null() {
        return ResourceIdentity::empty();
    }

    let transport = read_socket_transport(socket_ptr);
    let Ok(family) = (unsafe { bpf_probe_read_kernel(addr_of!((*address_ptr).sa_family)) }) else {
        return ResourceIdentity::empty();
    };

    match family {
        AF_INET => {
            let Ok(address) = (unsafe { bpf_probe_read_kernel(address_ptr.cast::<SockAddrIn>()) })
            else {
                return ResourceIdentity::empty();
            };
            let mut socket_ip = [0; SOCKET_IP_LEN];
            socket_ip[..4].copy_from_slice(&address.sin_addr);
            ResourceIdentity {
                file_device: 0,
                file_inode: 0,
                socket_family: SocketFamily::Inet,
                socket_transport: transport,
                socket_port: ntohs(address.sin_port),
                socket_ip,
            }
        }
        AF_INET6 => {
            let Ok(address) = (unsafe { bpf_probe_read_kernel(address_ptr.cast::<SockAddrIn6>()) })
            else {
                return ResourceIdentity::empty();
            };
            ResourceIdentity {
                file_device: 0,
                file_inode: 0,
                socket_family: SocketFamily::Inet6,
                socket_transport: transport,
                socket_port: ntohs(address.sin6_port),
                socket_ip: address.sin6_addr,
            }
        }
        _ => ResourceIdentity::empty(),
    }
}
