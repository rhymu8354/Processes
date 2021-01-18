use crate::ProcessInfo;
use std::{
    borrow::Borrow,
    collections::HashSet,
    ffi::c_void,
    os::raw::{
        c_int,
        c_longlong,
        c_short,
        c_uint,
        c_ushort,
    },
    path::PathBuf,
};

const AF_INET: c_int = 2;
const SOCKINFO_TCP: c_int = 2;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const TSI_T_NTIMERS: usize = 4;
const SOCK_MAXADDRLEN: usize = 255;
const IF_NAMESIZE: usize = 16;
const MAX_KCTL_NAME: usize = 96;

#[allow(non_camel_case_types)]
type pid_t = c_int;
#[allow(non_camel_case_types)]
type off_t = c_longlong;
#[allow(non_camel_case_types)]
type uid_t = c_uint;
#[allow(non_camel_case_types)]
type gid_t = c_uint;
#[allow(non_camel_case_types)]
type in_addr_t = c_uint;
#[allow(non_camel_case_types)]
type sa_family_t = u8;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct proc_fdinfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct proc_fileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: off_t,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct vinfo_stat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: uid_t,
    vst_gid: gid_t,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: off_t,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct sockbuf_info {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: c_short,
    sbi_timeo: c_short,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct in_addr {
    s_addr: in_addr_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
union u6_addr {
    __u6_addr8: [u8; 16],
    __u6_addr16: [u16; 8],
    __u6_addr32: [u32; 4],
}

impl Default for u6_addr {
    fn default() -> Self {
        Self {
            __u6_addr32: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct in6_addr {
    __u6_addr: u6_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct in4in6_addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: in_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
union insi_faddr_t {
    ina_46: in4in6_addr,
    ina_6: in6_addr,
}

impl Default for insi_faddr_t {
    fn default() -> Self {
        Self {
            ina_6: in6_addr::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
union insi_laddr_t {
    ina_46: in4in6_addr,
    ina_6: in6_addr,
}

impl Default for insi_laddr_t {
    fn default() -> Self {
        Self {
            ina_6: in6_addr::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct insi_v4_t {
    in4_tos: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct insi_v6_t {
    in6_hlim: u8,
    in6_cksum: c_int,
    in6_ifindex: c_ushort,
    in6_hops: c_short,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct in_sockinfo {
    insi_fport: c_int,
    insi_lport: c_int,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: insi_faddr_t,
    insi_laddr: insi_laddr_t,
    insi_v4: insi_v4_t,
    insi_v6: insi_v6_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct tcp_sockinfo {
    tcpsi_ini: in_sockinfo,
    tcpsi_state: c_int,
    tcpsi_timer: [c_int; TSI_T_NTIMERS],
    tcpsi_mss: c_int,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct sockaddr_un {
    sun_len: u8,
    sun_family: sa_family_t,
    sun_path: [u8; 104],
}

#[repr(C)]
#[derive(Clone, Copy)]
union unsi_addr_t {
    ua_sun: sockaddr_un,
    ua_dummy: [u8; SOCK_MAXADDRLEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
union unsi_caddr_t {
    ua_sun: sockaddr_un,
    ua_dummy: [u8; SOCK_MAXADDRLEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct un_sockinfo {
    unsi_conn_so: u64,
    unsi_conn_pcb: u64,
    unsi_addr: unsi_addr_t,
    unsi_caddr: unsi_caddr_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ndrv_info {
    ndrvsi_if_family: u32,
    ndrvsi_if_unit: u32,
    ndrvsi_if_name: [u8; IF_NAMESIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct kern_event_info {
    kesi_vendor_code_filter: u32,
    kesi_class_filter: u32,
    kesi_subclass_filter: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct kern_ctl_info {
    kcsi_id: u32,
    kcsi_reg_unit: u32,
    kcsi_flags: u32,
    kcsi_recvbufsize: u32,
    kcsi_sendbufsize: u32,
    kcsi_unit: u32,
    kcsi_name: [u8; MAX_KCTL_NAME],
}

#[repr(C)]
#[derive(Clone, Copy)]
union soi_proto_t {
    pri_in: in_sockinfo,
    pri_tcp: tcp_sockinfo,
    pri_un: un_sockinfo,
    pri_ndrv: ndrv_info,
    pri_kern_event: kern_event_info,
    pri_kern_ctl: kern_ctl_info,
}

impl Default for soi_proto_t {
    fn default() -> Self {
        Self {
            pri_in: in_sockinfo::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct socket_info {
    soi_stat: vinfo_stat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: c_int,
    soi_protocol: c_int,
    soi_family: c_int,
    soi_options: c_short,
    soi_linger: c_short,
    soi_state: c_short,
    soi_qlen: c_short,
    soi_incqlen: c_short,
    soi_qlimit: c_short,
    soi_timeo: c_short,
    soi_error: c_ushort,
    soi_oobmark: u32,
    soi_rcv: sockbuf_info,
    soi_snd: sockbuf_info,
    soi_kind: c_int,
    rfu_1: u32,
    soi_proto: soi_proto_t,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct socket_fdinfo {
    pfi: proc_fileinfo,
    psi: socket_info,
}

#[link(name = "proc")]
extern "C" {
    fn proc_listallpids(
        buffer: *const c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *const c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *const c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidpath(
        pid: c_int,
        buffer: *mut u8,
        buffersize: u32,
    ) -> c_int;
}

fn list_process_ids() -> Vec<pid_t> {
    let buffer_size = unsafe { proc_listallpids(std::ptr::null(), 0) };
    if buffer_size < 0 {
        return Vec::default();
    }
    #[allow(clippy::cast_sign_loss)]
    let mut pids = vec![0; buffer_size as usize];
    let buffer_size = unsafe {
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_possible_wrap)]
        proc_listallpids(
            pids.as_mut_ptr() as *const c_void,
            buffer_size * std::mem::size_of::<pid_t>() as c_int,
        )
    };
    #[allow(clippy::cast_sign_loss)]
    pids.truncate(buffer_size as usize);
    pids
}

fn process_image(pid: pid_t) -> PathBuf {
    let mut name_chars = vec![0; PROC_PIDPATHINFO_MAXSIZE];
    let buffer_size = unsafe {
        #[allow(clippy::cast_possible_truncation)]
        proc_pidpath(pid, name_chars.as_mut_ptr(), name_chars.len() as u32)
    };
    #[allow(clippy::cast_sign_loss)]
    name_chars.truncate(buffer_size as usize);
    PathBuf::from(String::from_utf8_lossy(&name_chars).to_string())
}

fn fd_socket_info(
    pid: pid_t,
    fd: proc_fdinfo,
) -> Option<socket_fdinfo> {
    let mut socket_info = socket_fdinfo::default();
    let socket_info_ptr: *mut socket_fdinfo = &mut socket_info;
    if unsafe {
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_possible_wrap)]
        proc_pidfdinfo(
            pid,
            fd.proc_fd,
            PROC_PIDFDSOCKETINFO,
            socket_info_ptr as *const c_void,
            std::mem::size_of::<socket_fdinfo>() as i32,
        )
    } >= 0
    {
        Some(socket_info)
    } else {
        None
    }
}

fn tcp_server_port<T: Borrow<socket_fdinfo>>(socket_info: T) -> Option<u16> {
    let socket_info = socket_info.borrow();
    if (socket_info.psi.soi_family == AF_INET)
        && (socket_info.psi.soi_kind == SOCKINFO_TCP)
        && unsafe {
            socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport == 0
        }
    {
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_sign_loss)]
        Some(
            unsafe {
                socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport as u16
            }
            .to_be(),
        )
    } else {
        None
    }
}

fn process_tcp_server_ports(pid: pid_t) -> HashSet<u16> {
    let buffer_size =
        unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null(), 0) };
    if buffer_size < 0 {
        return HashSet::default();
    }
    #[allow(clippy::cast_sign_loss)]
    let mut fds = vec![
        proc_fdinfo::default();
        buffer_size as usize / std::mem::size_of::<proc_fdinfo>()
    ];
    let buffer_size = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr() as *const c_void,
            buffer_size,
        )
    };
    #[allow(clippy::cast_sign_loss)]
    fds.truncate(buffer_size as usize / std::mem::size_of::<proc_fdinfo>());
    fds.into_iter()
        .filter(|fd| fd.proc_fdtype == PROX_FDTYPE_SOCKET)
        .filter_map(|fd| fd_socket_info(pid, fd))
        .filter_map(tcp_server_port)
        .collect()
}

#[must_use]
pub fn list_processes() -> Vec<ProcessInfo> {
    list_process_ids()
        .into_iter()
        .map(|pid| {
            #[allow(clippy::cast_sign_loss)]
            let id = pid as usize;
            ProcessInfo {
                id,
                image: process_image(pid),
                tcp_server_ports: process_tcp_server_ports(pid),
            }
        })
        .collect()
}
