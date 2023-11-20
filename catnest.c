/*
 *	catnest
 *	A substitution of systemd-sysusers
 *	This file is distributed under MIT License.
 *	Copyright (c) 2023 Yao Zi. All rights reserved.
 */

#include<assert.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<stdarg.h>

#ifdef __CATNEST_DEBUG__

#define PATH_PASSWD	"./passwd"
#define PATH_GROUP	"./group"

#endif	// __CATNEST_DEBUG__

#define do_if(cond, action) do { \
	if (cond) {					\
		action;					\
	}						\
} while (0)

#define frees(...) do { \
	void *_pList[] = { __VA_ARGS__ };					\
	for (unsigned int i = 0; i < sizeof(_pList) / sizeof(void *); i++)	\
		free(_pList[i]);					\
} while (0)

#define check(cond, ...) do_if(!(cond), do_log(__VA_ARGS__); exit(-1))

typedef struct {
	char *name;
	char *passwd;
	unsigned long int uid, gid;
	char *gecos;
	char *home;
	char *shell;
} User_Entry;

struct {
	User_Entry	*users;
	size_t		userNum, listSize;
} gUserList;

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

char *
strdup_f(const char *s)
{
	if (!s)
		return NULL;
	char *copy = strdup(s);
	check(copy, "Failed to allocate memory for duplicated string\n");
	return copy;
}

char *
str_split(char *s, const char *delim)
{
	static char *old = NULL;
	if (s)
		old = s;
	assert(old);
	if (!*old)
		return NULL;

	char *start = old;
	for (; *old; old++) {
		if (strchr(delim, *old)) {
			*old = '\0';
			old++;
			return start;
		}
	}
	return start;
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

static void
expand_user_list(void)
{
	if (gUserList.userNum == gUserList.listSize) {
		gUserList.listSize += 256;
		gUserList.users = realloc(gUserList.users,
					  sizeof(User_Entry) *
					  	gUserList.listSize);
		check(gUserList.users,
		      "Failed to allocate memory for user list");
	}
	return;
}

static void
add_user(User_Entry *entry)
{
	User_Entry u = *entry;
	expand_user_list();

	u.name		= strdup_f(u.name);
	u.passwd	= strdup_f(u.passwd);
	u.gecos		= strdup_f(u.gecos);
	u.home		= strdup_f(u.home);
	u.shell		= strdup_f(u.shell);

	gUserList.users[gUserList.userNum] = u;
	gUserList.userNum++;
	return;
}

void
load_passwd(void)
{
	FILE *passwd = fopen(PATH_PASSWD, "r");

	char *line	= NULL;
	size_t length	= 0;
	while (getline(&line, &length, passwd) > 0) {
		if (length > 0 && line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		User_Entry u = { NULL };
		char *suid, *sgid;
		char **p[] = {
				&u.name, &u.passwd, &suid, &sgid, &u.gecos,
				&u.home, &u.shell, NULL
			    };
		int i = 0;
		for (char *part = str_split(line, ":"); part && i < 7; i++) {
			*p[i] = part;
			part = str_split(NULL, ":");
		}

		check(i == 7, "misformed line in passwd\n");

		printf("name: %s, passwd %s, uid %lu. gid %lu, gecos %s"
		       " home %s, shell %s\n",
		       u.name, u.passwd, u.uid, u.gid, u.gecos, u.home, u.shell);
		add_user(&u);
		free(line);
		line = NULL;
	}
	free(line);

	fclose(passwd);
}

void
unload_passwd(void)
{
	for (size_t i = 0; i < gUserList.userNum; i++) {
		User_Entry *u = gUserList.users + i;
		frees(u->name, u->passwd, u->gecos, u->home, u->shell);
	}
	free(gUserList.users);
}

int
main(int argc, const char *argv[])
{
	do_if(argc != 2, return -1);
	load_passwd();
	unload_passwd();
	parse_sysuser_conf(argv[1]);
	return 0;
}
