<img src="assets/NSS-128x128.png" align="right" />

# DLLSpy

> *This is a fork of the fantastic [`DLLSpy`](https://github.com/cyberark/DLLSpy) project by CyberArk and contributors.*

[![MSBuild](https://github.com/nefarius/DLLSpy/actions/workflows/msbuild.yml/badge.svg)](https://github.com/nefarius/DLLSpy/actions/workflows/msbuild.yml)

## Why fork

Made a few major changes to better fit my own needs of the tool:

- The scan results are printed to `STDOUT` as valid JSON and can therefore easily digested and further processed by whatever analysis tools you want to chain the results into 🔥
- The tool status and potential error messages are printed to `STDERR` only, so they will never end up in and mangle the JSON results ✅
- Modernized and sped up the code by updating to modern C++ paradigms ⚡
- Added a version resource, a little pet peeve of mine 😉

## How to use

I recommend to run the tool in an elevated PowerShell session and pipe the scan results into the `ConvertFrom-Json` cmdlet, like:

```PowerShell
.\DLLSpy.exe -d -s | ConvertFrom-Json
```

This will give you true objects for each discovered process you can explore or further process in whatever way you can imagine!
