# catnest

A substitution for ``systemd-sysusers``

## Features

- Small size (less than 500 cloc), single file
- systemd-free
- POSIX compatible

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

- Support option 'u' and 'g' only, 'r' is ignored
- File path in ID field is not supported
- All GECOS need to be quoted (even it does ***NOT*** content a blank character)
- gshadow files are not completely supported, but ``catnest`` will append to it
when needed. All existed group passwords will be ***ERASED***.

## About

``catnest`` is a part of eweOS project, mainly developed by Ziyao.

The source is distributed under MIT License.

For more information about the configuration file, see the manual of
``systemd-sysusers``.
