#!/bin/sh

cc catnest.c -o catnest -g -O0 -Wextra -std=gnu99 -Wall		\
	-Werror -D__CATNEST_DEBUG -pedantic			\
	-Wno-missing-field-initializers
