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
pub use windows::start_detached;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::TryFrom as _,
        env::current_exe,
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

    struct TestArea {}

    impl TestArea {
        fn new() -> Self {
            let _ = create_dir(
                [
                    current_exe().unwrap().parent().unwrap(),
                    Path::new("TestArea"),
                ]
                .iter()
                .collect::<PathBuf>(),
            );
            Self {}
        }
    }

    impl Drop for TestArea {
        fn drop(&mut self) {
            let _ = remove_dir_all(
                [
                    current_exe().unwrap().parent().unwrap(),
                    Path::new("TestArea"),
                ]
                .iter()
                .collect::<PathBuf>(),
            );
        }
    }

    #[test]
    fn detached() {
        // Start the detached process.
        let test_area = TestArea::new();
        let args = vec![
            String::from("detached"),
            String::from("abc"),
            String::from("def ghi"),
        ];
        let reported_pid = start_detached(
            [
                current_exe().unwrap().parent().unwrap(),
                Path::new("mock_subprocess"),
            ]
            .iter()
            .collect::<PathBuf>(),
            &args,
        );
        assert_ne!(0, reported_pid);

        // Wait a short period of time so that we don't race the detached
        // process.
        sleep(Duration::from_millis(250));

        // Verify process ID matches what the detached process says it has.
        let pid = read_to_string(
            [
                current_exe().unwrap().parent().unwrap(),
                Path::new("TestArea"),
                Path::new("pid"),
            ]
            .iter()
            .collect::<PathBuf>(),
        )
        .unwrap();
        let pid = pid.trim().parse::<usize>().unwrap();
        assert_eq!(pid, reported_pid);

        // Verify command-line arguments given to the detached process match
        // what it says it received.
        let lines = BufReader::new(
            File::open(
                [
                    current_exe().unwrap().parent().unwrap(),
                    Path::new("TestArea"),
                    Path::new("foo.txt"),
                ]
                .iter()
                .collect::<PathBuf>(),
            )
            .unwrap(),
        )
        .lines()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
        assert_eq!(args, lines);

        // Linux and Mac targets also know what file handles are open, so check
        // to make sure none are in the detached process.
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            0,
            read_to_string(
                [
                    current_exe().unwrap().parent().unwrap(),
                    Path::new("TestArea"),
                    Path::new("handles")
                ]
                .iter()
                .collect::<PathBuf>()
            )
            .unwrap()
            .trim()
            .parse::<usize>()
            .unwrap()
        );
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
