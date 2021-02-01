//! This crate provides several free functions for managing other processes
//! running in the host operating system:
//!
//! * [`list_processes`] &ndash; poll the operating system for a list of the
//!   current running processes, along with paths to the primary image
//!   (executable file) of each process and the set of TCP server ports
//!   currently bound by each process
//! * [`start_detached`] &ndash; start a new process that inherits no file
//!   handles and operates in its own session
//! * [`kill`] &ndash; terminate another process
//!
//! [`list_processes`]: fn.list_processes.html
//! [`start_detached`]: fn.start_detached.html
//! [`kill`]: fn.kill.html

#![warn(clippy::pedantic)]
#![warn(missing_docs)]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix;
#[cfg(target_os = "windows")]
mod windows;

use std::{
    collections::HashSet,
    ffi::OsStr,
    path::{
        Path,
        PathBuf,
    },
};

/// This holds information about one running process managed by the operating
/// system.
pub struct ProcessInfo {
    /// This is the identifier of the process, which can be given to [`kill`]
    /// to terminate the process.
    ///
    /// [`kill`]: fn.kill.html
    pub id: usize,

    /// This is the path in the filesystem of the primary image (executable
    /// file) of the process.
    pub image: PathBuf,

    /// This is the set of TCP server ports currently bound by the process.
    pub tcp_server_ports: HashSet<u16>,
}

#[cfg(target_os = "linux")]
use linux::close_all_files_except;
#[cfg(target_os = "linux")]
use linux::list_processes_internal;

#[cfg(target_os = "macos")]
use macos::close_all_files_except;
#[cfg(target_os = "macos")]
use macos::list_processes_internal;

#[cfg(unix)]
use unix::kill_internal;
#[cfg(unix)]
use unix::start_detached_internal;

#[cfg(target_os = "windows")]
use windows::kill_internal;
#[cfg(target_os = "windows")]
use windows::list_processes_internal;
#[cfg(target_os = "windows")]
use windows::start_detached_internal;

/// Poll the operating system to return information about all currently running
/// processes.
pub fn list_processes() -> impl Iterator<Item = ProcessInfo> {
    list_processes_internal()
}

/// Start a new process that inherits no file handles and runs in an
/// independent session.  The caller provides the `path` of the primary
/// executable to run in the new process, as well as any `args` (arguments)
/// to provide the new process on its command line.
pub fn start_detached<P, A, S>(
    path: P,
    args: A,
) -> usize
where
    P: AsRef<Path>,
    A: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    start_detached_internal(path, args)
}

/// Terminate the process with the given `pid` (process identifier).
pub fn kill(pid: usize) {
    kill_internal(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::TryFrom as _,
        env::current_exe,
        ffi::OsString,
        fs::{
            create_dir,
            read_to_string,
            remove_dir_all,
            File,
        },
        io::{
            BufRead,
            BufReader,
        },
        net::{
            Ipv4Addr,
            TcpListener,
        },
        path::Path,
        thread::sleep,
        time::Duration,
    };

    struct TestArea {
        path: PathBuf,
    }

    impl TestArea {
        fn path(&self) -> &Path {
            &self.path
        }

        fn new() -> Self {
            let path = [
                current_exe().unwrap().parent().unwrap(),
                Path::new(&uuid::Uuid::new_v4().to_string()),
            ]
            .iter()
            .collect();
            let _ = create_dir(&path);
            Self {
                path,
            }
        }
    }

    impl Drop for TestArea {
        fn drop(&mut self) {
            let _ = remove_dir_all(&self.path);
        }
    }

    #[test]
    fn detached() {
        // Set up the test area where the detached process will write
        // its report files.
        let test_area = TestArea::new();

        // Find the mock subprocess.
        let mock_subprocess = PathBuf::from(
            String::from_utf8_lossy(
                &std::process::Command::new("cargo")
                    .args(&["run", "--bin", "mock_subprocess", "--", "where"])
                    .output()
                    .unwrap()
                    .stdout,
            )
            .to_string(),
        );

        // Start the detached process.
        let args = vec![
            OsString::from("detached"),
            test_area.path().as_os_str().to_owned(),
            OsString::from("abc"),
            OsString::from("def ghi"),
        ];
        let reported_pid = start_detached(mock_subprocess, &args);
        assert_ne!(0, reported_pid);

        // Wait a short period of time so that we don't race the detached
        // process.
        sleep(Duration::from_millis(250));

        // Verify process ID matches what the detached process says it has.
        let pid = read_to_string(
            [test_area.path(), Path::new("pid")].iter().collect::<PathBuf>(),
        )
        .unwrap();
        let pid = pid.trim().parse::<usize>().unwrap();
        assert_eq!(pid, reported_pid);

        // Verify command-line arguments given to the detached process match
        // what it says it received.
        let lines = BufReader::new(
            File::open(
                [test_area.path(), Path::new("args")]
                    .iter()
                    .collect::<PathBuf>(),
            )
            .unwrap(),
        )
        .lines()
        .map(Result::unwrap)
        .map(OsString::from)
        .collect::<Vec<_>>();
        assert_eq!(args, lines);

        // UNIX-like targets also know what file handles are open, so check
        // to make sure none are in the detached process.
        #[cfg(unix)]
        {
            let handles = read_to_string(
                [test_area.path(), Path::new("handles")]
                    .iter()
                    .collect::<PathBuf>(),
            )
            .unwrap();
            assert_eq!(0, handles.len(), "Handles: {}", handles);
        }
        drop(test_area);
    }

    #[test]
    fn find_self_by_image_path() {
        let mut processes = list_processes();
        let self_path = current_exe().unwrap().canonicalize().unwrap();
        let self_id = usize::try_from(std::process::id()).unwrap();
        assert!(processes.any(|process| {
            process.image == self_path && process.id == self_id
        }));
    }

    #[test]
    fn find_self_by_tcp_server_port() {
        let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        let mut processes = list_processes();
        let self_id = usize::try_from(std::process::id()).unwrap();
        assert!(processes.any(|process| {
            process.tcp_server_ports.contains(&port) && process.id == self_id
        }));
    }
}
