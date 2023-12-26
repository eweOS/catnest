#!/bin/sh

gcc catnest.c -o catnest -g -O0 -Wextra -std=gnu99 -Wall	\
	-Werror
