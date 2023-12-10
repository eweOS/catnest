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
#include<stdbool.h>

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
#define warn_if(cond, action, ...) do_if(cond, do_log(__VA_ARGS__); action)
#define DO_RETURN return;

#define expand_list(list, entry, num, size) do {			\
	if (list.num == list.size) {					\
		list.size += 256;					\
		list.entry = realloc(list.entry,			\
				     sizeof(*list.entry) *		\
				     	   list.size);			\
		check(list.entry,					\
		      "Failed to alloate memory for " #list "\n");	\
	}								\
} while (0)

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

typedef struct {
	char type;
	char *name;
	char *id;
	char *gecos;
	char *home;
	char *shell;
} Action;

struct {
	Action *special;	// Entries with id speicifed
	Action *other;
	size_t specialSize, specialNum;
	size_t otherSize, otherNum;
} gActionList;

typedef struct ID_Range {
	unsigned long int start, end;
	struct ID_Range *next;
} ID_Range;

struct {
	unsigned long int start, end;
	ID_Range *ranges;
} gIDPool;

unsigned long int gIDRangeStart = ID_RANGE_START, gIDRangeEnd = ID_RANGE_END;

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
set_id_range(char *conf[5])
{
	warn_if(!conf[1], DO_RETURN,
		"A range must be specified for type 'r'\n");
	char *sEnd = NULL;
	unsigned long int start = strtol(conf[1], &sEnd, 0);
	warn_if(*sEnd != '-', DO_RETURN, "Invalid range for type 'r'\n");
	sEnd++;
	warn_if(!*sEnd, DO_RETURN, "Invalid range for type 'r'\n");
	unsigned long int end = strtol(sEnd, &sEnd, 0);
	warn_if(*sEnd || end < start, DO_RETURN, "Invalid range for type 'r'\n");

	gIDRangeStart	= start;
	gIDRangeEnd	= end;

	return;
}


void
add_action(char opt, char *conf[5])
{
	if (opt == 'r') {
		set_id_range(conf);
		return;
	}

	Action a = {
			.type	= opt,
			.name	= strdup_f(conf[0]),
			.id	= strdup_f(conf[1]),
			.gecos	= strdup_f(conf[2]),
			.home	= strdup_f(conf[3]),
			.shell	= strdup_f(conf[4]),
		   };
	if (opt != 'm' && conf[1]) {
		expand_list(gActionList, special, specialNum, specialSize);
		gActionList.special[gActionList.specialNum] = a;
		gActionList.specialNum++;
	} else {
		expand_list(gActionList, other, otherNum, otherSize);
		gActionList.other[gActionList.otherNum] = a;
		gActionList.otherNum++;
	}
	return;
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

	add_action(opt, conf);

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

User_Entry *
get_user_by_name(const char *name)
{
	for (size_t i = 0; i < gUserList.userNum; i++) {
		if (!strcmp(name, gUserList.users[i].name))
			return gUserList.users + i;
	}
	return NULL;
}

User_Entry *
get_user_by_id(unsigned long int uid)
{
	for (size_t i = 0; i < gUserList.userNum; i++) {
		if (gUserList.users[i].uid == uid)
			return gUserList.users + i;
	}
	return NULL;
}

void
load_passwd(void)
{
	FILE *passwd = fopen(PATH_PASSWD, "r");
	check(passwd, "Cannot open passwd file %s for reading\n",
	      PATH_PASSWD);

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
	FILE *fp = fopen(PATH_PASSWD, "w");
	check(fp, "Cannot open passwd file %s for writing", PATH_PASSWD);
	for (size_t i = 0; i < gUserList.userNum; i++) {
		User_Entry *u = gUserList.users + i;
		fprintf(fp, "%s:%s:%lu:%lu:%s:%s:%s\n",
			u->name, u->passwd, u->uid, u->gid, u->gecos,
			u->home, u->shell);
		frees(u->name, u->passwd, u->gecos, u->home, u->shell);
	}
	free(gUserList.users);
	fclose(fp);
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
	g.passwd	= strdup_f(g.passwd);
	g.members	= strdup_f(g.members);

	gGroupList.groups[gGroupList.groupNum] = g;
	gGroupList.groupNum++;

	return;
}

Group_Entry *
get_group_by_name(const char *name)
{
	for (size_t i = 0; i < gGroupList.groupNum; i++) {
		if (!strcmp(gGroupList.groups[i].name, name))
			return gGroupList.groups + i;
	}
	return NULL;
}

Group_Entry *
get_group_by_id(unsigned long int gid)
{
	for (size_t i = 0; i < gGroupList.groupNum; i++) {
		if (gGroupList.groups[i].gid == gid)
			return gGroupList.groups + i;
	}
	return NULL;
}

int
is_in_group(const Group_Entry *group, const User_Entry *user)
{
	char *p = strstr(group->members, user->name);
	return p					&&
	       (p == group->members || p[-1] == ',')	&&
	       (p[strlen(user->name)] == '\0' || p[strlen(user->name)] == ',');
}

void
load_group(void)
{
	FILE *groupf = fopen(PATH_GROUP, "r");
	check(groupf, "Cannot open group file %s for reading\n",
	      PATH_GROUP);

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
	FILE *fp = fopen(PATH_GROUP, "w");
	check(fp, "Cannot open group file %s for writing\n", PATH_GROUP);
	for (size_t i = 0; i < gGroupList.groupNum; i++) {
		Group_Entry *g = gGroupList.groups + i;
		fprintf(fp, "%s:%s:%lu:%s\n",
			g->name, g->passwd, g->gid, g->members);
		frees(g->name, g->passwd, g->members);
	}
	free(gGroupList.groups);
	fclose(fp);
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

void
do_action_add_user(Action *a)
{
	/*	The user already exists		*/
	if (get_user_by_name(a->name))
		return;

	unsigned long int uid, gid;
	bool ok = false, gidSpecified = false;
	if (a->id) {
		char *end = NULL;
		uid = strtol(a->id, &end, 0);

		if (*end == ':') {
			end++;
			warn_if(!*end, DO_RETURN,
				"Invalid UID:GID pair %s\n", a->id);
			gid = strtol(a->id, &end, 0);
			warn_if(!*end, DO_RETURN,
				"Invalid UID:GID pair %s\n", a->id);
			gidSpecified = true;
		} else {
			warn_if(*end, DO_RETURN,
				"Invalid UID %s", a->id);
		}

		ok = !get_user_by_id(uid);
	}

	if (!ok && gidSpecified) {
		if (!get_user_by_id(gid)) {
			uid	= gid;
			ok	= true;
		}
	}

	if (!ok) {
		uid = idpool_get();
		idpool_use(uid);
	}

	if (gidSpecified) {
		if (!get_group_by_id(gid)) {
			add_group(&(Group_Entry)
				{
					.name		= a->name,
					.gid		= gid,
					.passwd		= "!",
					.members	= "",
				});
		}
	} else {
		Group_Entry *group = get_group_by_name(a->name);
		if (group) {
			gid = group->gid;
		} else {
			if (!get_group_by_id(uid)) {
				gid = uid;
			} else {
				gid = idpool_get();
				idpool_use(gid);
				add_group(&(Group_Entry)
					{
						.name		= a->name,
						.gid		= gid,
						.passwd		= "!",
						.members	= "",
					});
			}
		}
	}

	add_user(&(User_Entry) {
					.name	= a->name,
					.passwd	= "!",
					.uid	= uid,
					.gid	= gid,
					.gecos	= a->gecos,
					.home	= a->home ? a->home : "/",
					.shell	= a->shell	? a->shell  :
						  uid == 0	? "/bin/sh" :
						  	"/usr/sbin/nologin",
				});

	return;
}

void
do_action_add_group(Action *a)
{
	if (get_group_by_name(a->name))
		return;

	unsigned long int gid;
	if (a->id) {
		char *end = NULL;
		gid = strtol(a->id, &end, 0);
		warn_if(*end, DO_RETURN, "Invalid GID %s\n", a->id);
	} else {
		gid = idpool_get();
		idpool_use(gid);
	}

	add_group(&(Group_Entry) {
					.name		= a->name,
					.passwd		= "!",
					.gid		= gid,
					.members	= "",
				 });
	return;
}

void
do_action(Action *a)
{
	printf("%c: %s | %s | %s | %s | %s\n", a->type,
	       a->name, a->id, a->gecos, a->home, a->shell);

	switch (a->type) {
	case 'u':
		do_action_add_user(a);
		break;
	case 'g':
		do_action_add_group(a);
		break;
	case 'm':
		do_log("Type m is not supported\n");
		break;
	}

	return;
}

void
do_actions(void)
{
	puts("Special actions");
	for (size_t i = 0; i < gActionList.specialNum; i++) {
		Action *a = gActionList.special + i;
		do_action(a);
		frees(a->name, a->id, a->gecos, a->home, a->shell);
	}

	puts("Other actions");
	for (size_t i = 0; i < gActionList.otherNum; i++) {
		Action *a = gActionList.other + i;
		do_action(a);
		frees(a->name, a->id, a->gecos, a->home, a->shell);
	}

	frees(gActionList.special, gActionList.other);
	return;
}

int
main(int argc, const char *argv[])
{
	do_if(argc != 2, return -1);

	load_passwd();
	load_group();

	idpool_init(gIDRangeStart, gIDRangeEnd);

	parse_sysuser_conf(argv[1]);

	do_actions();

	idpool_destroy();
	unload_group();
	unload_passwd();
	return 0;
}
