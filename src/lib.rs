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
