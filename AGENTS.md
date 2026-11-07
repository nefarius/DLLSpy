# AGENTS.md

Guidance for AI coding agents working in this repository.

## Contribution rules

- Do new work on a descriptively named branch (`feat/...`, `fix/...`, `chore/...`) created from an up-to-date `master`. Never commit new work directly to `master`. Deliver it through a pull request.
- Use Conventional Commits (`feat:`, `fix:`, `build:`, `ci:`, `docs:`, `chore:`, `refactor:`).
- Source and config files (`.cpp`, `.h`, `.rc`, `.vcxproj`, `.sln`, `.json`, `.yml`, `.bat`, `.md`, `.props`, `.targets`) must be UTF-8 without a BOM. Editors and agent tools on Windows can silently write UTF-16 LE (a `FF FE` BOM, or `NUL` bytes between ASCII characters). After creating or overwriting a file, check the on-disk bytes and convert UTF-16 or a UTF-8 BOM to UTF-8 without a BOM before continuing.

## Build

DLLSpy is a Visual Studio 2022 (toolset v143) console application. Dependencies come from vcpkg manifest mode (`vcpkg.json` at the repo root) and are linked statically.

1. `git submodule update --init vcpkg`
2. From a Developer Command Prompt, run `prepare-deps.bat` to install `x86-windows-static`, `x64-windows-static`, and `arm64-windows-static`. Pass `x86`, `x64`, or `ARM64` to install a single triplet. The first build from Visual Studio can fail with D8050 when vcpkg cannot see the compiler; running this script once avoids that.
3. `msbuild DLLSpy.sln /p:Configuration=Release /p:Platform=x64 /m`

Solution platforms are `x86` (the project platform is `Win32`), `x64`, and `ARM64`. Release output is `bin\<platform>\DLLSpy.exe`. The code is C++20 with warning level 4. Angle-bracket includes are external headers, so warnings from the Windows SDK and jsoncpp are not part of a clean build.

`prepare-deps.bat` uses `VCPKG_CACHE_PATH` as a vcpkg binary cache when that variable is set. CI sets it.

`triplets\` overlays the static triplets and pins `VCPKG_PLATFORM_TOOLSET` to v143. `Directory.Build.props` passes that overlay to the MSBuild vcpkg install. Without it, a machine that also has a newer toolset builds jsoncpp with that toolset and the link fails with an unresolved `__std_find_trivial_1`.

## Bumping vcpkg

The `vcpkg` submodule commit and the `baseline` in `vcpkg-configuration.json` must move together. Dependabot does not update the submodule, because an automatic submodule bump would drift away from the baseline.

1. Inside `vcpkg/`, check out the new microsoft/vcpkg release tag.
2. Set `default-registry.baseline` in `vcpkg-configuration.json` to that commit (`git -C vcpkg rev-parse HEAD`).
3. Run `prepare-deps.bat` and build all three platforms.

## Versioning and releases

`DLLSpy/DLLSpy.rc` in git stays at a placeholder version. CI stamps it with [vpatch](https://www.nuget.org/packages/Nefarius.Tools.Vpatch) before building: `vX.Y.Z` tags stamp `X.Y.Z`, and every other build stamps `1.1.<run_number>`.

Pushing a `vX.Y.Z` tag (for example `v1.1.0`) builds x86, x64, and ARM64, signs the three executables with SignRelay, and publishes `DLLSpy_vX.Y.Z.zip`. The `SIGN_RELAY_CI_TOKEN` secret must be set on the repository. Do not push a tag unless a signed release is intended.
