use crate::ProcessInfo;
use std::{
    borrow::Cow,
    collections::{
        HashMap,
        HashSet,
    },
    ffi::{
        c_void,
        OsStr,
        OsString,
    },
    iter::{
        once,
        repeat,
    },
    os::windows::{
        ffi::OsStringExt as _,
        prelude::OsStrExt as _,
    },
    path::{
        Path,
        PathBuf,
    },
};

type HANDLE = *const c_void;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;
const NO_ERROR: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const MIB_TCP_STATE_LISTEN: u32 = 2;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const PROCESS_TERMINATE: u32 = 0x0001;

#[repr(C)]
#[allow(non_snake_case)]
struct MIB_TCPROW2 {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
    dwOffloadState: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct MIB_TCPTABLE2 {
    dwNumEntries: u32,
    table: [MIB_TCPROW2; 1],
}

#[link(name = "psapi")]
extern "C" {
    fn EnumProcesses(
        lpidProcess: *mut u32,
        cb: u32,
        lpcbNeeded: *mut u32,
    ) -> bool;
}

#[link(name = "kernel32")]
extern "C" {
    fn OpenProcess(
        dwDesiredAccess: u32,
        bInheritHandle: bool,
        dwProcessId: u32,
    ) -> HANDLE;
    fn CloseHandle(hObject: HANDLE) -> bool;
    fn TerminateProcess(
        hProcess: HANDLE,
        uExitCode: u32,
    ) -> bool;
    fn QueryFullProcessImageNameW(
        hProcess: HANDLE,
        dwFlags: u32,
        lpExeName: *mut u16,
        lpdwSize: *mut u32,
    ) -> bool;
    fn CreateProcessW(
        lpApplicationName: *const u16,
        lpCommandLine: *const u16,
        lpProcessAttributes: *const SECURITY_ATTRIBUTES,
        lpThreadAttributes: *const SECURITY_ATTRIBUTES,
        bInheritHandles: bool,
        dwCreationFlags: u32,
        lpEnvironment: *const c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *const STARTUPINFOW,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> bool;
}

#[link(name = "Iphlpapi")]
extern "C" {
    fn GetTcpTable2(
        TcpTable: *mut MIB_TCPTABLE2,
        SizePointer: *mut u32,
        Order: bool,
    ) -> u32;
}

#[allow(non_snake_case)]
#[repr(C)]
struct STARTUPINFOW {
    cb: u32,
    lpReserved: *const u16,
    lpDesktop: *const u16,
    lpTitle: *const u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *const u8,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
}

#[allow(non_snake_case)]
#[repr(C)]
struct PROCESS_INFORMATION {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: u32,
    dwThreadId: u32,
}

#[allow(non_snake_case)]
#[repr(C)]
struct SECURITY_ATTRIBUTES {
    nLength: u32,
    lpSecurityDescriptor: *const c_void,
    bInheritHandle: bool,
}

struct SafeHandle(HANDLE);

impl SafeHandle {
    fn ok(&self) -> Option<HANDLE> {
        if self.0 == std::ptr::null() {
            None
        } else {
            Some(self.0)
        }
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if self.0 != std::ptr::null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn list_process_ids() -> Vec<u32> {
    let mut process_ids = vec![0_u32; 1024];
    loop {
        let mut bytes_needed: u32 = 0;
        unsafe {
            #[allow(clippy::cast_possible_truncation)]
            if !EnumProcesses(
                process_ids.as_mut_ptr(),
                (process_ids.len() * 4) as u32,
                &mut bytes_needed,
            ) {
                return vec![];
            }
        }
        if bytes_needed as usize == process_ids.len() * 4 {
            process_ids.resize(process_ids.len() * 2, 0);
        } else {
            process_ids.resize((bytes_needed / 4) as usize, 0);
            break process_ids;
        }
    }
}

fn list_tcp_server_ports_per_process() -> HashMap<u32, HashSet<u16>> {
    let mut tcp_server_ports = HashMap::new();
    let mut required_tcp_table_size = 4096;
    let mut tcp_table_buffer = vec![];
    let get_tcp_table_result = loop {
        tcp_table_buffer.resize(required_tcp_table_size as usize, 0);
        let get_tcp_table_result = unsafe {
            GetTcpTable2(
                tcp_table_buffer.as_mut_ptr() as *mut MIB_TCPTABLE2,
                &mut required_tcp_table_size,
                false,
            )
        };
        if get_tcp_table_result != ERROR_INSUFFICIENT_BUFFER {
            break get_tcp_table_result;
        }
    };
    if get_tcp_table_result == NO_ERROR {
        let tcp_table = tcp_table_buffer.as_mut_ptr() as *const MIB_TCPTABLE2;
        let num_entries = unsafe { (*tcp_table).dwNumEntries };
        for i in 0..num_entries {
            let i = i as usize;
            let tcp_table_entry =
                unsafe { (*tcp_table).table.get_unchecked(i) };
            if tcp_table_entry.dwState == MIB_TCP_STATE_LISTEN {
                #[allow(clippy::cast_possible_truncation)]
                tcp_server_ports
                    .entry(tcp_table_entry.dwOwningPid)
                    .or_insert_with(HashSet::new)
                    .insert((tcp_table_entry.dwLocalPort as u16).to_be());
            }
        }
    }
    tcp_server_ports
}

fn open_process(id: u32) -> SafeHandle {
    SafeHandle(unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, id)
    })
}

fn query_full_process_image_name(process: HANDLE) -> PathBuf {
    let mut exe_image_path: Vec<u16> = vec![0; 256];
    #[allow(clippy::cast_possible_truncation)]
    loop {
        let mut actual_length = exe_image_path.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(
                process,
                0,
                exe_image_path.as_mut_ptr(),
                &mut actual_length,
            )
        } {
            exe_image_path.truncate(actual_length as usize);
            break PathBuf::from(OsString::from_wide(&exe_image_path))
                .canonicalize()
                .unwrap();
        } else {
            exe_image_path.resize(exe_image_path.len() * 2, 0);
        }
    }
}

#[must_use]
pub fn list_processes() -> Vec<ProcessInfo> {
    let mut tcp_server_ports = list_tcp_server_ports_per_process();
    list_process_ids()
        .into_iter()
        .map(|id| ProcessInfo {
            id: id as usize,
            image: open_process(id)
                .ok()
                .map_or_else(PathBuf::new, query_full_process_image_name),
            tcp_server_ports: tcp_server_ports.remove(&id).unwrap_or_default(),
        })
        .collect()
}

fn make_command_line<P, A, S>(
    path: P,
    args: A,
) -> Vec<u16>
where
    P: AsRef<Path>,
    A: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command_line = Vec::new();
    let path = path.as_ref().as_os_str().encode_wide().collect::<Vec<_>>();
    if path.iter().any(|ch| *ch == 0x0022 /* '"' */) {
        command_line.push(0x0022);
        command_line.extend(path.iter());
        command_line.push(0x0022);
    } else {
        command_line.extend(path.iter());
    }
    for arg in args {
        command_line.push(0x0020 /* ' ' */);
        let arg = arg.as_ref().encode_wide().collect::<Vec<_>>();
        if arg
            .iter()
            .any(|ch| [0x0020, 0x0009, 0x000A, 0x000B, 0x0022].contains(ch))
        {
            command_line.push(0x0022);
            let mut slash_count = 0;
            for ch in arg {
                if ch == 0x005C
                // '\\'
                {
                    slash_count += 1;
                } else {
                    command_line.extend(repeat(0x005C).take(slash_count));
                    if ch == 0x0022 {
                        command_line
                            .extend(repeat(0x005C).take(slash_count + 1));
                    }
                    command_line.push(ch);
                    slash_count = 0;
                }
            }
            if slash_count > 0 {
                command_line.extend(repeat(0x005C).take(slash_count * 2));
            }
            command_line.push(0x0022);
        } else {
            command_line.extend(arg.iter());
        }
    }
    command_line.push(0);
    command_line
}

pub fn start_detached<P, A, S>(
    path: P,
    args: A,
) -> usize
where
    P: AsRef<Path>,
    A: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // Add file extension because that part is platform-specific.
    let mut path = Cow::from(path.as_ref());
    match path.as_ref().extension() {
        Some(extension) if extension == "exe" => {},
        _ => {
            path.to_mut().set_extension("exe");
        },
    }

    let command_line = make_command_line(&path, args);

    // Launch program.
    #[allow(clippy::cast_possible_truncation)]
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpReserved: std::ptr::null(),
        lpDesktop: std::ptr::null(),
        lpTitle: std::ptr::null(),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: 0,
        wShowWindow: 0,
        cbReserved2: 0,
        lpReserved2: std::ptr::null(),
        hStdInput: std::ptr::null(),
        hStdOutput: std::ptr::null(),
        hStdError: std::ptr::null(),
    };
    let mut pi = PROCESS_INFORMATION {
        hProcess: std::ptr::null(),
        hThread: std::ptr::null(),
        dwProcessId: 0,
        dwThreadId: 0,
    };
    let path =
        path.as_os_str().encode_wide().chain(once(0)).collect::<Vec<_>>();
    let success = unsafe {
        CreateProcessW(
            path.as_ptr(),
            command_line.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            false,
            DETACHED_PROCESS,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if success {
        unsafe {
            CloseHandle(pi.hProcess);
        }
        pi.dwProcessId as usize
    } else {
        0
    }
}

pub fn kill(pid: usize) {
    #[allow(clippy::cast_possible_truncation)]
    let process_handle =
        unsafe { OpenProcess(PROCESS_TERMINATE, false, pid as u32) };
    if process_handle == std::ptr::null() {
        return;
    }
    unsafe {
        TerminateProcess(process_handle, 255);
        CloseHandle(process_handle);
    }
}
