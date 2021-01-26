use crate::close_all_files_except;
use std::{
    ffi::{
        CString,
        OsStr,
    },
    iter::once,
    os::unix::ffi::OsStrExt as _,
    path::Path,
};

#[allow(clippy::similar_names)]
pub fn start_detached<P, A, S>(
    path: P,
    args: A,
) -> usize
where
    P: AsRef<Path>,
    A: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut pipe_ends = [0; 2];
    if unsafe { libc::pipe(pipe_ends.as_mut_ptr()) } < 0 {
        return 0;
    }
    let child_args = once(path.as_ref().to_path_buf().into_os_string())
        .chain(args.into_iter().map(|arg| arg.as_ref().to_owned()))
        .map(|arg| CString::new(arg.as_bytes()).unwrap())
        .collect::<Vec<_>>();
    let child = unsafe { libc::fork() };
    match child {
        0 => {
            close_all_files_except(pipe_ends[1]);
            unsafe { libc::setsid() };
            let grandchild = unsafe { libc::fork() };
            match grandchild {
                0 => {
                    unsafe { libc::close(pipe_ends[1]) };
                    let program = CString::new(
                        path.as_ref().to_path_buf().into_os_string().as_bytes(),
                    )
                    .unwrap();
                    let argv = child_args
                        .iter()
                        .map(|arg| arg.as_ptr())
                        .chain(once(std::ptr::null()))
                        .collect::<Vec<_>>();
                    unsafe {
                        libc::execv(program.as_ptr(), argv.as_ptr());
                        libc::exit(-1);
                    }
                },
                grandchild if grandchild < 0 => {
                    unsafe { libc::exit(-1) };
                },
                _ => {},
            };
            unsafe {
                libc::write(
                    pipe_ends[1],
                    &grandchild as *const i32 as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>(),
                );
                libc::exit(0);
            }
        },
        child if child < 0 => {
            unsafe {
                libc::close(pipe_ends[0]);
                libc::close(pipe_ends[1]);
            }
            return 0;
        },
        _ => {},
    };
    unsafe { libc::close(pipe_ends[1]) };
    let mut child_status = 0;
    unsafe { libc::waitpid(child, &mut child_status as *mut libc::c_int, 0) };
    if libc::WEXITSTATUS(child_status) != 0 {
        unsafe { libc::close(pipe_ends[0]) };
        return 0;
    }
    let mut detached_process_id: libc::c_uint = 0;
    let read_amount = unsafe {
        libc::read(
            pipe_ends[0],
            &mut detached_process_id as *mut libc::c_uint as *mut libc::c_void,
            std::mem::size_of::<libc::c_uint>(),
        )
    };
    unsafe { libc::close(pipe_ends[0]) };
    #[allow(clippy::cast_sign_loss)]
    if read_amount as usize == std::mem::size_of::<libc::c_uint>() {
        detached_process_id as usize
    } else {
        0
    }
}
