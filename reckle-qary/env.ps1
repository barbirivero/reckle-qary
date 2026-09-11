# Build environment for reckle-qary on Windows (x86_64-pc-windows-gnu).
#
# Two things this fixes:
#  1. A stale 32-bit MinGW under C:\MinGW (if present) shadows the linker that
#     rustup ships and breaks the build with "Invalid bfd target" / "CreateProcess".
#     We drop it from PATH and let rustc use its own self-contained toolchain.
#  2. Building inside a OneDrive-synced folder is slow and can hit file locks, so
#     the cargo target directory is redirected outside of it.
#
# The toolchain itself is pinned by rust-toolchain.toml (nightly, required by
# plonky2_field's `#![feature(specialization)]`).
#
# Usage:  . .\env.ps1

$clean = ($env:Path -split ';') | Where-Object { $_ -and ($_ -notmatch '^C:\\MinGW') }
$env:Path = (@("$env:USERPROFILE\.cargo\bin") + $clean) -join ';'
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\rust-target\reckle-qary"

Write-Host "cargo:  $((Get-Command cargo).Source)"
Write-Host "target: $env:CARGO_TARGET_DIR"
