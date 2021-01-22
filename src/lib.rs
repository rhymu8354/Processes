#![warn(clippy::pedantic)]
// TODO: Remove this once ready to publish.
#![allow(clippy::missing_errors_doc)]
// TODO: Uncomment this once ready to publish.
//#![warn(missing_docs)]

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

use std::{
    collections::HashSet,
    path::PathBuf,
};

pub struct ProcessInfo {
    pub id: usize,
    pub image: PathBuf,
    pub tcp_server_ports: HashSet<u16>,
}

#[cfg(target_os = "linux")]
pub use linux::list_processes;

#[cfg(target_os = "macos")]
pub use macos::list_processes;

#[cfg(target_os = "windows")]
pub use windows::list_processes;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::TryFrom as _,
        env::current_exe,
        net::{
            Ipv4Addr,
            TcpListener,
        },
    };

    #[test]
    fn find_self_by_image_path() {
        let processes = list_processes();
        let self_path = current_exe().unwrap().canonicalize().unwrap();
        let self_id = usize::try_from(std::process::id()).unwrap();
        assert!(processes.iter().any(|process| {
            process.image == self_path && process.id == self_id
        }));
    }

    #[test]
    fn find_self_by_tcp_server_port() {
        let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        let processes = list_processes();
        let self_id = usize::try_from(std::process::id()).unwrap();
        assert!(processes.iter().any(|process| {
            process.tcp_server_ports.contains(&port) && process.id == self_id
        }));
    }
}
