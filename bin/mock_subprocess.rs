#![warn(clippy::pedantic)]

use std::{
    env::{
        args_os,
        current_exe,
    },
    fs::File,
    io::Write as _,
    path::{
        Path,
        PathBuf,
    },
    process::exit,
};

fn main() {
    let mut f = File::create(
        [
            current_exe().unwrap().parent().unwrap(),
            Path::new("TestArea"),
            Path::new("pid"),
        ]
        .iter()
        .collect::<PathBuf>(),
    )
    .unwrap();
    let _ = writeln!(&mut f, "{}", std::process::id());
    drop(f);
    let args = args_os().skip(1).collect::<Vec<_>>();
    match args.first() {
        Some(arg) if arg == "detached" => {
            let mut f = File::create(
                [
                    current_exe().unwrap().parent().unwrap(),
                    Path::new("TestArea"),
                    Path::new("foo.txt"),
                ]
                .iter()
                .collect::<PathBuf>(),
            )
            .unwrap();
            for arg in &args {
                let _ = writeln!(&mut f, "{}", arg.to_string_lossy());
            }
            exit(0)
        },
        _ => exit(1),
    }
}
