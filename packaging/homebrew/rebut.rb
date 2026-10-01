# Homebrew formula template for rebut.
#
# The release workflow (.github/workflows/release.yml) replaces the @...@
# placeholders with the tag's version and the sha256 of each release tarball,
# then pushes the result to LaloNchera22/homebrew-tap as Formula/rebut.rb:
#
#   brew install LaloNchera22/tap/rebut
class Rebut < Formula
  desc "Check that a Rust change does what it claims by running base and head"
  homepage "https://lalonchera22.github.io/rebut/"
  version "@VERSION@"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/LaloNchera22/rebut/releases/download/v#{version}/rebut-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256_AARCH64_APPLE_DARWIN@"
    end
    on_intel do
      url "https://github.com/LaloNchera22/rebut/releases/download/v#{version}/rebut-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256_X86_64_APPLE_DARWIN@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/LaloNchera22/rebut/releases/download/v#{version}/rebut-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_AARCH64_LINUX_MUSL@"
    end
    on_intel do
      url "https://github.com/LaloNchera22/rebut/releases/download/v#{version}/rebut-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_X86_64_LINUX_MUSL@"
    end
  end

  def install
    bin.install "rebut", "rebut-mcp"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/rebut --version")
    assert_match "pre-push", shell_output("#{bin}/rebut hook --help")
  end
end
