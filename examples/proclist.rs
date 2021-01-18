use rhymuproc::list_processes;

fn main() {
    for process in list_processes() {
        println!(
            "{}: {}; {:?}",
            process.id,
            process.image.to_string_lossy(),
            process.tcp_server_ports
        );
    }
}
