# typed: false
# frozen_string_literal: true

# Homebrew Formula for SecretHarbor
# Documentation: https://docs.brew.sh/Formula-Cookbook
class Secretharbor < Formula
  desc "Host-level security boundary and secret virtualization layer for AI agents"
  homepage "https://secretharbor.dev"
  url "https://github.com/secretharbor/secretharbor/archive/refs/tags/v0.4.0-prod.tar.gz"
  version "0.4.0-prod"
  license "Apache-2.0"
  head "https://github.com/secretharbor/secretharbor.git", branch: "main"

  depends_on "go" => :build

  def install
    # Build binaries using local Go toolchain
    system "go", "build", "-ldflags=-s -w", "-o", "bin/shb", "./cmd/shb"
    system "go", "build", "-ldflags=-s -w", "-o", "bin/secretharbor", "./cmd/secretharbor"

    # Install binaries
    bin.install "bin/shb"
    bin.install "bin/secretharbor"

    # Generate and install Unix manual pages
    system "go", "run", "./cmd/gen-man", "man/man1"
    man1.install Dir["man/man1/*.1"]
  end

  test do
    assert_match "SecretHarbor", shell_output("#{bin}/shb version")
    assert_match "SecretHarbor", shell_output("#{bin}/secretharbor version")
    assert_match "Protection: standard", shell_output("#{bin}/shb config --json")
  end
end
