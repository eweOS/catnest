# catnest

A substitution for ``systemd-sysusers``

## Features

- Small size (less than 500 cloc), single file
- systemd-free
- Mostly POSIX compatible

## Installation

Available on eweOS

```shell
pacman -S catnest
```

To compile from source, simply run

```shell
cc catnest.c -o catnest
```

## Differences from systemd-sysusers

- catnest doesn't create users or groups mentioned in 'm' entires implicitly.
- File paths in ID field are not supported
- All GECOS strings need quotation, even if they do ***NOT*** contain a blank
  character)
- gshadow files are not completely supported, but `catnest` will append to it
  if necessary. All existed group passwords will be ***ERASED***.

## About

`catnest` is a part of eweOS project, mainly developed by
`Yao Zi <ziyao@disroot.org>`.

The source is distributed under MIT License.

For more information about the configuration file, see the manual of
``systemd-sysusers``.
