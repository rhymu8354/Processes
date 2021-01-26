#![warn(clippy::pedantic)]

#[cfg(target_os = "linux")]
use std::fs::{
    read_dir,
    read_link,
};
use std::{
    env::{
        args_os,
        current_exe,
    },
    ffi::OsString,
    fs::File,
    io::Write as _,
    path::{
        Path,
        PathBuf,
    },
    process::exit,
};

#[cfg(target_os = "macos")]
const PROC_PIDLISTFDS: libc::c_int = 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct proc_fdinfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
extern "C" {
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffer_size: libc::c_int,
    ) -> libc::c_int;
}

fn record_our_pid<P: AsRef<Path>>(path: P) {
    let mut f = File::create(
        [path.as_ref(), Path::new("pid")].iter().collect::<PathBuf>(),
    )
    .unwrap();
    let _ = writeln!(&mut f, "{}", std::process::id());
}

fn record_our_args<P: AsRef<Path>, A: IntoIterator<Item = OsString>>(
    path: P,
    args: A,
) {
    let mut f = File::create(
        [path.as_ref(), Path::new("args")].iter().collect::<PathBuf>(),
    )
    .unwrap();
    for arg in args {
        let _ = writeln!(&mut f, "{}", arg.to_string_lossy());
    }
}

#[cfg(target_os = "windows")]
fn record_our_handles<P: AsRef<Path>>(_path: P) {}

#[cfg(target_os = "linux")]
fn record_our_handles<P: AsRef<Path>>(path: P) {
    let fds = read_dir("/proc/self/fd/")
        .map(|dir_entries| {
            dir_entries
                .filter_map(|dir_entry| {
                    dir_entry.ok().and_then(|dir_entry| {
                        dir_entry
                            .file_name()
                            .to_str()
                            .and_then(|fd| fd.parse::<usize>().ok())
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let dev_null = PathBuf::from("/dev/null");
    let report = fds
        .into_iter()
        .filter_map(|fd| {
            read_link(format!("/proc/self/fd/{}", fd))
                .ok()
                .filter(|link| fd > 2 || *link != dev_null)
                .map(|link| format!("{}: {}", fd, link.to_string_lossy()))
        })
        .collect::<Vec<_>>();
    let mut f = File::create(
        [path.as_ref(), Path::new("handles")].iter().collect::<PathBuf>(),
    )
    .unwrap();
    for line in report {
        let _ = writeln!(&mut f, "{}", line);
    }
}

#[cfg(target_os = "macos")]
fn record_our_handles<P: AsRef<Path>>(path: P) {
    let pid = unsafe { libc::getpid() };
    let buffer_size = unsafe {
        proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    };
    if buffer_size < 0 {
        return;
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
            fds.as_mut_ptr() as *mut libc::c_void,
            buffer_size,
        )
    };
    if buffer_size < 0 {
        return;
    }
    #[allow(clippy::cast_sign_loss)]
    fds.truncate(buffer_size as usize / std::mem::size_of::<proc_fdinfo>());
    let report = fds
        .into_iter()
        .filter_map(|fd| {
            if fd.proc_fd > 2 {
                Some(format!("{}", fd.proc_fd))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let mut f = File::create(
        [path.as_ref(), Path::new("handles")].iter().collect::<PathBuf>(),
    )
    .unwrap();
    for line in report {
        let _ = writeln!(&mut f, "{}", line);
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    let args = args_os().skip(1).collect::<Vec<_>>();
    match args.first() {
        Some(command) if command == "detached" => {
            let path = PathBuf::from(args.get(1).unwrap());
            record_our_pid(&path);
            record_our_args(&path, args);
            record_our_handles(&path);
            exit(0)
        },
        Some(command) if command == "where" => {
            print!("{}", current_exe().unwrap().to_string_lossy());
        },
        _ => exit(1),
    }
}
