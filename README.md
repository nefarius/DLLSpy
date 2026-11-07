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

Run DLLSpy from an elevated shell. Findings are JSON on stdout. Progress and errors go to stderr.

```PowerShell
.\DLLSpy.exe -d -s | ConvertFrom-Json
```

### Options

- `-d` (required) checks DLLs loaded by running processes.
- `-s` reads the import and delay-import tables of running processes and services.
- `-t`, together with `-s`, also scans binaries for `.dll` strings. Those references are low confidence and are tagged `"source": "string"`.
- `-a` includes processes that run as you without elevation. They are omitted by default, because replacing a DLL there does not cross a privilege boundary.
- `-r n` repeats the static scan `n` levels into referenced DLLs (`n` below 5).

### Severity

A DLL is reported only when the process runs as another account, as `SYSTEM`, or elevated, and you could write that DLL.

| Severity | Meaning |
| --- | --- |
| `high` | The DLL is already in a directory you can write, or it is missing and the application directory is writable. |
| `medium` | The DLL is missing, the application directory is protected, and an earlier directory on the machine `PATH` is writable. |

DLLs that already exist under `C:\Windows`, `C:\Windows\System32`, or `C:\Windows\System` are not reported. API-set names (`api-ms-*`, `ext-ms-*`) and `KnownDLLs` are ignored.

### JSON

Each application has `application`, `path`, `user`, `elevated`, and `sameUser`. `user` is the account the process or service runs as. Each module has `path`, `severity`, and `source` (`loaded`, `import`, `delay-import`, or `string`). `writableDir` is present when a writable directory was identified.

## Build

The project builds with Visual Studio 2022 (toolset v143) and vcpkg in manifest mode. From a Developer Command Prompt:

```bat
git submodule update --init vcpkg
prepare-deps.bat
msbuild DLLSpy.sln /p:Configuration=Release /p:Platform=x64 /m
```

`prepare-deps.bat` with no argument installs the static triplets for x86, x64, and ARM64. Pass `x86`, `x64`, or `ARM64` to install just one. Release binaries land in `bin\<platform>\DLLSpy.exe`.
