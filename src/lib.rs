#![warn(clippy::pedantic)]
// TODO: Remove this once ready to publish.
#![allow(clippy::missing_errors_doc)]
// TODO: Uncomment this once ready to publish.
//#![warn(missing_docs)]

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
    path::PathBuf,
};

pub struct ProcessInfo {
    pub id: usize,
    pub image: PathBuf,
    pub tcp_server_ports: HashSet<u16>,
}

#[cfg(target_os = "linux")]
use linux::close_all_files_except;
#[cfg(target_os = "linux")]
pub use linux::list_processes;

#[cfg(target_os = "macos")]
use macos::close_all_files_except;
#[cfg(target_os = "macos")]
pub use macos::list_processes;

#[cfg(unix)]
pub use unix::start_detached;

#[cfg(target_os = "windows")]
pub use windows::list_processes;
#[cfg(target_os = "windows")]
pub use windows::start_detached;

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
