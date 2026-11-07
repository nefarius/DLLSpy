# <img src="assets/NSS-128x128.png" align="left" /> DLLSpy

[![Build status](https://github.com/nefarius/DLLSpy/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/nefarius/DLLSpy/actions/workflows/build.yml)
[![GitHub All Releases](https://img.shields.io/github/downloads/nefarius/DLLSpy/total)](https://github.com/nefarius/DLLSpy/releases)
[![Discord](https://img.shields.io/discord/346756263763378176.svg)](https://discord.nefarius.at)
[![GitHub followers](https://img.shields.io/github/followers/nefarius.svg?style=social&label=Follow)](https://github.com/nefarius)

DLLSpy detects DLL hijacking in running processes, services and in their binaries.

> *This is a fork of the fantastic [`DLLSpy`](https://github.com/cyberark/DLLSpy) project by CyberArk and contributors.*

## Why fork

Made a few major changes to better fit my own needs of the tool:

- The scan results are printed to `STDOUT` as valid JSON and can therefore easily digested and further processed by whatever analysis tools you want to chain the results into
- The tool status and potential error messages are printed to `STDERR` only, so they will never end up in and mangle the JSON results
- Modernized and sped up the code by updating to modern C++ paradigms
- Added a version resource, a little pet peeve of mine

## Download

Signed builds for x86, x64, and ARM64 are attached to each [GitHub release](https://github.com/nefarius/DLLSpy/releases). A release is published when a `vX.Y.Z` tag is pushed. The zip contains `x86\DLLSpy.exe`, `x64\DLLSpy.exe`, and `ARM64\DLLSpy.exe`.

## How to use

I recommend to run the tool in an elevated PowerShell session and pipe the scan results into the `ConvertFrom-Json` cmdlet, like:

```PowerShell
.\DLLSpy.exe -d -s | ConvertFrom-Json
```

This will give you true objects for each discovered process you can explore or further process in whatever way you can imagine!

## Build

The project builds with Visual Studio 2022 (toolset v143) and vcpkg in manifest mode. From a Developer Command Prompt:

```bat
git submodule update --init vcpkg
prepare-deps.bat
msbuild DLLSpy.sln /p:Configuration=Release /p:Platform=x64 /m
```

`prepare-deps.bat` with no argument installs the static triplets for x86, x64, and ARM64. Pass `x86`, `x64`, or `ARM64` to install just one. Release binaries land in `bin\<platform>\DLLSpy.exe`.
