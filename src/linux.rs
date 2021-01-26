use std::{
    collections::{
        HashMap,
        HashSet,
    },
    fs::{
        read_dir,
        read_link,
        File,
    },
    io::{
        BufRead as _,
        BufReader,
    },
};

use crate::ProcessInfo;

fn match_socket_fd_name<T: AsRef<str>>(fd_name: T) -> Option<usize> {
    fd_name
        .as_ref()
        .strip_prefix("socket:[")
        .and_then(|socket_fd_name_suffix| {
            socket_fd_name_suffix.strip_suffix("]")
        })
        .and_then(|inode| usize::from_str_radix(&inode, 10).ok())
}

fn tcp_server_ports_for_process(
    pid: usize,
    inodes_to_tcp_server_ports: &HashMap<usize, u16>,
) -> HashSet<u16> {
    read_dir(format!("/proc/{}/fd/", pid))
        .map(|dir_entries| {
            dir_entries
                .filter_map(|dir_entry| {
                    dir_entry
                        .ok()
                        .and_then(|dir_entry| read_link(dir_entry.path()).ok())
                        .and_then(|contents| {
                            contents
                                .into_os_string()
                                .into_string()
                                .ok()
                                .and_then(match_socket_fd_name)
                        })
                        .and_then(|inode| {
                            inodes_to_tcp_server_ports.get(&inode).copied()
                        })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[must_use]
pub fn list_processes() -> Vec<ProcessInfo> {
    let mut inodes_to_tcp_server_ports = HashMap::new();
    if let Ok(tcp_table) = File::open("/proc/net/tcp") {
        for line in BufReader::new(tcp_table).lines().filter_map(Result::ok) {
            let mut line_parts = line.split_whitespace().skip(1);
            let port_info = line_parts.next();
            let mut line_parts = line_parts.skip(1);
            let status = line_parts.next();
            let mut line_parts = line_parts.skip(5);
            let inode = line_parts.next();
            if let (Some(port_info), Some(status), Some(inode)) =
                (port_info, status, inode)
            {
                if let (
                    Some(Ok(local_port)),
                    Ok(10), // TCP_LISTEN
                    Ok(inode),
                ) = (
                    port_info
                        .split(':')
                        .nth(1)
                        .map(|local_port| u16::from_str_radix(local_port, 16)),
                    u8::from_str_radix(status, 16),
                    usize::from_str_radix(inode, 10),
                ) {
                    inodes_to_tcp_server_ports.insert(inode, local_port);
                }
            }
        }
    }
    read_dir("/proc/")
        .map(|dir_entries| {
            dir_entries
                .filter_map(|dir_entry| {
                    dir_entry
                        .ok()
                        .and_then(|dir_entry| {
                            dir_entry.file_name().to_str().map(str::to_owned)
                        })
                        .and_then(|file_name| file_name.parse::<usize>().ok())
                        .and_then(|id| {
                            read_link(format!("/proc/{}/exe", id))
                                .ok()
                                .map(|image| (id, image))
                        })
                        .map(|(id, image)| ProcessInfo {
                            id,
                            image,
                            tcp_server_ports: tcp_server_ports_for_process(
                                id,
                                &inodes_to_tcp_server_ports,
                            ),
                        })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn close_all_files_except(keep_open: libc::c_int) {
    if let Ok(dir_entries) = read_dir("/proc/self/fd/") {
        for dir_entry in dir_entries {
            if let Some(fd_num) = dir_entry
                .ok()
                .and_then(|dir_entry| {
                    dir_entry.file_name().to_str().map(str::to_owned)
                })
                .and_then(|file_name| file_name.parse::<libc::c_int>().ok())
            {
                if fd_num != keep_open {
                    unsafe { libc::close(fd_num) };
                }
            };
        }
    }
}
