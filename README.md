## About

selfLock is a free and open-source application for Windows that lets you block **your own** access to distracting websites, your mail servers, or anything else on the Internet. Just set a period of time to block for, add sites or applications to your blocklist, and click "Start Block". Until that timer expires, you will be unable to access those sites — even if you restart your computer or close the application.

Tick **Application blocking** to also block selected programs (for example `firefox.exe`) with Windows Firewall rules. While a block is active, those applications can be started but cannot reach the network.

## Credits

Originally developed for macOS by [Charlie Stigler](http://charliestigler.com), [Steve Lambert](http://visitsteve.com), and [others](https://github.com/SelfControlApp/selfcontrol/graphs/contributors). This is a Windows port written in Rust, based on the original project's blocking model and file formats.

## Contributors

See [CONTRIBUTORS.md](./CONTRIBUTORS.md).

## License

SelfLock is free software under the GPL. See [this file](./COPYING) for more details.

## Building For Development

Users should download the latest version from the GitHub releases page. If you want to contribute, you can build it on Windows with a recent stable Rust toolchain:

1. Clone this repository from GitHub.
2. Install Rust from [rustup.rs](https://rustup.rs/).
3. Build the release binary: `cargo build --release`
4. Run `target\release\selflock.exe`.
5. Run the checks before submitting changes: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.

> With the GNU toolchain, install MinGW-w64 binutils so `dlltool.exe` is on `PATH`, or use the MSVC toolchain with the Visual C++ Build Tools.
