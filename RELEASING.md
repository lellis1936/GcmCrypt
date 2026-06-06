# Releasing GcmCrypt

This file is for maintainers preparing release assets.

## Build Release Assets

Run:

    .\scripts\package-release.ps1

The script writes release assets to:

    release-assets\

## Assets To Upload

Upload these two files:

    GcmCrypt-net48.exe
    GcmCrypt-net8-win-x64-self-contained.exe

## Asset Notes

`GcmCrypt-net48.exe` is intended for Windows 10/11 machines with .NET Framework 4.8 available.

`GcmCrypt-net8-win-x64-self-contained.exe` is the trimmed, compressed, self-contained `win-x64` build and does not require a .NET runtime installation.

## Create GitHub Release

Existing GitHub releases are left untouched. To create a new release, install GitHub CLI, authenticate, commit the release changes, merge them to `master`, make sure the working tree is clean, then run:

    gh auth login
    .\scripts\publish-github-release.ps1 -Version 1.4.0

The script:

- verifies GitHub CLI authentication
- requires the working tree to be clean
- builds release assets
- creates and pushes an annotated tag such as `v1.4.0`
- creates a GitHub Release titled `Version 1.4.0` with the two release assets
