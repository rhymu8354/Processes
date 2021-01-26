# Processes (rhymuproc)

This library supports discovering the processes running in the operating system
and interacting with them.

[![Crates.io](https://img.shields.io/crates/v/rhymuproc.svg)](https://crates.io/crates/rhymuproc)
[![Documentation](https://docs.rs/rhymuproc/badge.svg)][dox]

The following features are currently supported:

* Getting a list of the currently running processes, including their
  identifiers, paths to their images (executable files), and sets of TCP server
  ports currently bound by them.
* Starting a new detached process (separate session, not connected to the
  process which started it, and inheriting no file handles).
* Killing a process selected by identifier.

The following operating systems are supported:

* Microsoft Windows
* Linux
* MacOS

More information about the Rust implementation of this library can be found in
the [crate documentation][dox].

[dox]: https://docs.rs/rhymuproc

## License

Licensed under the [MIT license](LICENSE.txt).
