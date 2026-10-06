# typed: false
# frozen_string_literal: true

class Shb < Formula
  desc "Host-level security boundary for AI agents"
  homepage "https://github.com/logn10/SecretHarbor"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/logn10/SecretHarbor/releases/download/v#{version}/secretharbor_#{version}_darwin_arm64.tar.gz"
    else
      url "https://github.com/logn10/SecretHarbor/releases/download/v#{version}/secretharbor_#{version}_darwin_amd64.tar.gz"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/logn10/SecretHarbor/releases/download/v#{version}/secretharbor_#{version}_linux_arm64.tar.gz"
    else
      url "https://github.com/logn10/SecretHarbor/releases/download/v#{version}/secretharbor_#{version}_linux_amd64.tar.gz"
    end
  end

  def install
    bin.install "shb"
    bin.install "secretharbor"
    man1.install Dir["man/man1/*.1"] if Dir.exist?("man/man1")
  end

  def caveats
    <<~EOS
      To initialize SecretHarbor for your projects and AI agents:
        shb init
    EOS
  end

  test do
    assert_match "SecretHarbor", shell_output("#{bin}/shb version")
    assert_match "SecretHarbor", shell_output("#{bin}/secretharbor version")
  end
end
