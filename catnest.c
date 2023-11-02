/*
 *	catnest
 *	A substitution of systemd-sysusers
 *	This file is distributed under MIT License.
 *	Copyright (c) 2023 Yao Zi. All rights reserved.
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<stdarg.h>

#define do_if(cond, action) do { \
	if (cond) {					\
		action;					\
	}						\
} while (0)

#define check(cond, ...) do_if(!(cond), do_log(__VA_ARGS__); exit(-1))

void
do_log(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	return;
}

static inline int
is_space(char c)
{
	return c == ' ' || c == '\t';
}

const char *
skip_space(const char *p)
{
	while (is_space(*p))
		p++;
	return p;
}

const char *
until_space(const char *p)
{
	while (!is_space(*p) && *p)
		p++;
	return p;
}

void
parse_sysuser_line(const char *line)
{
	line = skip_space(line);

	char opt = line[0];
	do_if(opt == '\0' || opt == '#', return);

	if (!strchr("ugmr", opt)) {
		do_log("failed to parse sysuser configuration:\n");
		do_log(isprint(opt) ? "'%c' %s" : "'\\%d' %s",
		       opt, "is not a valid type\n");
		return;
	}

	line++;
	char *conf[5] = { NULL };
	for (int i = 0; *line && i < 5; i++) {
		line = skip_space(line);
		if (!*line)
			break;

		size_t length;
		const char *end = line;
		if (*line == '"') {
			line++;
			end++;
			while (*end != '"') {
				if (*end == '\0')
					goto out;
				end++;
			}
			length = end - line;
			end++;
		} else {
			end = until_space(line);
			length = end - line;
		}

		conf[i] = malloc(length + 1);
		strncpy(conf[i], line, length);
		conf[i][length] = '\0';
		line = end;

		if (!strcmp(conf[i], "-")) {
			free(conf[i]);
			conf[i] = NULL;
		}
	}

	printf("%c: %s | %s | %s | %s | %s\n", opt, conf[0], conf[1], conf[2],
					       conf[3], conf[4]);

out:
	for (int i = 0; i < 5; i++)
		free(conf[i]);

	return;
}

void
parse_sysuser_conf(const char *path)
{
	FILE *fp = fopen(path, "r");
	check(fp, "Failed to open sysuser configuration file %s\n", path);

	char *line = NULL;
	size_t length;
	while (getline(&line, &length, fp) > 0) {
		if (length > 0 && line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';
		parse_sysuser_line(line);
		free(line);
		line = NULL;
	}
	free(line);

	fclose(fp);

	return;
}

int
main(int argc, const char *argv[])
{
	do_if(argc != 2, return -1);
	parse_sysuser_conf(argv[1]);
	return 0;
}
