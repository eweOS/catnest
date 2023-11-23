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

#define ID_RANGE_START	0
#define ID_RANGE_END	65536

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

typedef struct {
	char *name;
	char *passwd;
	unsigned long int gid;
	char *members;
} Group_Entry;

struct {
	Group_Entry	*groups;
	size_t		groupNum, listSize;
} gGroupList;

typedef struct ID_Range {
	unsigned long int start, end;
	struct ID_Range *next;
} ID_Range;

struct {
	unsigned long int start, end;
	ID_Range *ranges;
} gIDPool;

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

char *
remove_trailing_newline(char *s)
{
	if (strlen(s) > 0 && s[strlen(s) - 1] == '\n')
		s[strlen(s) - 1] = '\0';
	return s;
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
		remove_trailing_newline(line);

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

		u.uid = strtol(suid, NULL, 0);
		u.gid = strtol(sgid, NULL, 0);

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

void
expand_group_list(void)
{
	if (gGroupList.groupNum == gGroupList.listSize) {
		gGroupList.listSize += 256;
		gGroupList.groups =
			realloc(gGroupList.groups,
				sizeof(Group_Entry) * gGroupList.listSize);
		check(gGroupList.groups,
		      "cannot allocate memory for group list");
	}

	return;
}

void
add_group(Group_Entry *group)
{
	expand_group_list();

	Group_Entry g = *group;
	g.name		= strdup_f(g.name);
	g.passwd	= strdup_f(g.name);
	g.members	= strdup_f(g.members);

	gGroupList.groups[gGroupList.groupNum] = g;
	gGroupList.groupNum++;

	return;
}

void
load_group(void)
{
	FILE *groupf = fopen(PATH_GROUP, "r");
	check(groupf, "cannot open group file\n");

	char *line = NULL;
	size_t length;
	while (getline(&line, &length, groupf) > 0) {
		remove_trailing_newline(line);

		Group_Entry g = { NULL };
		char *gid = NULL;
		char **p[] = { &g.name, &g.passwd, &gid, &g.members };

		int i = 0;
		for (char *part = str_split(line, ":"); part && i < 4; i++) {
			*p[i] = part;
			part = str_split(NULL, ":");
		}

		if (i == 3) {
			i++;
			g.members = "";
		}

		check(i == 4, "misformed line in group\n");

		g.gid = strtol(gid, NULL, 0);

		add_group(&g);

		printf("name %s, passwd %s, gid %lu, members %s\n",
		       g.name, g.passwd, g.gid, g.members);

		free(line);
		line = NULL;
	}
	free(line);

	fclose(groupf);
}

void
unload_group(void)
{
	for (size_t i = 0; i < gGroupList.groupNum; i++) {
		Group_Entry *g = gGroupList.groups + i;
		frees(g->name, g->passwd, g->members);
	}
	free(gGroupList.groups);
}

static ID_Range *
idpool_new_range(unsigned long int start,
		 unsigned long int end,
		 ID_Range *next)
{
	ID_Range *range = malloc(sizeof(ID_Range));
	check(range, "failed to allocate memory for id range\n");
	*range = (ID_Range) {
				.start	= start,
				.end	= end,
				.next	= next,
			      };
	return range;
}

void
idpool_use(unsigned long int id)
{
	check(id >= gIDPool.start && id <= gIDPool.end,
	      "required id out of valid range\n");
	check(gIDPool.ranges, "no ID available");

	ID_Range *r = gIDPool.ranges, **lastNext = &gIDPool.ranges;
	while (r && !(id >= r->start && id <= r->end)) {
		lastNext = &r->next;
		r = r->next;
	}

	check(r && id >= r->start && id <= r->end,
	      "id %lu is not available\n", id);

	if (id == r->start || id == r->end) {
		r->start++;
	} else if (id == r->end) {
		r->end--;
	} else {
		ID_Range *new = idpool_new_range(id + 1, r->end, r->next);
		r->end = id - 1;
		r->next = new;
	}

	if (r->start > r->end) {
		*lastNext = r->next;
		free(r);
	}

	return;
}

unsigned long int
idpool_get(void)
{
	check(gIDPool.ranges, "no id available\n");
	return gIDPool.ranges->start;
}

void
idpool_init(unsigned long int start, unsigned long int end)
{
	gIDPool.ranges	= idpool_new_range(start, end, NULL);
	gIDPool.start	= start;
	gIDPool.end	= end;

	for (size_t i = 0; i < gUserList.userNum; i++) {
		unsigned long int id = gUserList.users[i].uid;
		if (id >= start || id <= end)
			idpool_use(id);
	}

	return;
}

void
idpool_destroy(void)
{
	ID_Range *range = gIDPool.ranges;
	while (range) {
		ID_Range *next = range->next;
		free(range);
		range = next;
	}
	return;
}

int
main(int argc, const char *argv[])
{
	do_if(argc != 2, return -1);

	load_passwd();
	load_group();

	idpool_init(ID_RANGE_START, ID_RANGE_END);
	idpool_destroy();

	parse_sysuser_conf(argv[1]);
	unload_group();
	unload_passwd();
	return 0;
}
