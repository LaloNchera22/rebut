# Install

rebut ships two binaries:

- `rebut`, the command line tool;
- `rebut-mcp`, an [MCP](https://modelcontextprotocol.io) server that exposes
  the same checks to coding agents.

Both need `git` and a Rust toolchain (`cargo`) on the `PATH`, because rebut
builds your code with your toolchain.

## From crates.io

```sh
cargo install rebut --locked        # the CLI
cargo install rebut-mcp --locked    # the MCP server, if you want it
```

## Prebuilt binaries

Every [GitHub Release](https://github.com/LaloNchera22/rebut/releases) has a
tarball per platform with both binaries and a `.sha256` file:

| Platform | Asset |
|---|---|
| Linux x86_64 (static, any distribution) | `rebut-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 (static) | `rebut-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple Silicon | `rebut-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `rebut-x86_64-apple-darwin.tar.gz` |

```sh
target=x86_64-unknown-linux-musl
base=https://github.com/LaloNchera22/rebut/releases/latest/download
curl -fsSLO "$base/rebut-$target.tar.gz"
curl -fsSLO "$base/rebut-$target.tar.gz.sha256"
sha256sum -c "rebut-$target.tar.gz.sha256"     # macOS: shasum -a 256 -c
tar -xzf "rebut-$target.tar.gz"
install -m 0755 "rebut-$target/rebut" "rebut-$target/rebut-mcp" ~/.local/bin/
```

There is no native Windows build: the local executor uses Unix process APIs.
On Windows, use WSL and the Linux binary.

## Homebrew

```sh
brew install LaloNchera22/tap/rebut
```

This installs both `rebut` and `rebut-mcp` (macOS and Linux).

## From source

```sh
git clone https://github.com/LaloNchera22/rebut
cd rebut
cargo install --locked --path crates/cli
cargo install --locked --path crates/mcp
```

## Check the install

```sh
rebut --version
rebut verify --help
```
