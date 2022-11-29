/*
 *	catnest
 *	A substitution for systemd-sysusers
 *	Date:2022.11.30
 *	File:/catnest.c
 *	By MIT License.
 *	Copyright (c) 2022 Ziyao.
 *	This program is a part of eweOS Project.
 */

#define _POSIX_C_SOURCE 200809L

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<unistd.h>

#define CONF_PATH_PASSWD	"./passwd"
#define CONF_PATH_GROUP		"./group"

static FILE *gLogStream = NULL;
#define check(assertion,action,...) do {				\
	if (!(assertion)) {						\
		fprintf(gLogStream,__VA_ARGS__)				\
		action;							\
	} } while(0)

/*
 *	name:password:uid:gid:comment:home:shell
 */
static inline struct passwd next_user(FILE *passwd)
{
	struct passwd user;
	fscanf(passwd,"%ms:%ms:%d:%d:%ms:%ms",&user->pw_username,
	       &user->pw_passwd,user->pw_uid,user->pw_gid,&user->pw_gecos,
	       &user->pw_dir,&user->pw_shell);
	return user;
}

static inline void passwd_destroy(struct passwd user)
{
	free(user->pw_username);
	free(user->pw_passwd);
	free(user->pw_gecos);
	free(user->pw_dir);
	free(user->pw_shell);
	return;
}

static struct passwd get_user_by_uid(FILE *passwd,int uid)
{
	struct passwd user;
	while (!feof(passwd)) {
		if (user->uid == uid)
			break;
		user = next_user(passwd);
	}

	rewind(passwd);
	return user;
}

static struct passwd get_user_by_name(FILE *passwd,const char *name)
{
	struct passwd user;
	while (!feof(passwd)) {
		if (!strcmp(user->name,name))
			break;

		user = next_user(passwd);
	}

	rewind(passwd);
	return user;
}

typedef struct {
	char *name;
	int gid;
	char *members;
} Group;

/*
 *	groupname:password:gid:userlist
 */
static inline Group next_group(FILE *groupFile)
{
	struct Group group;
	fscanf(groupFile,"%ms:%*s:%d:%ms",&group->name,&group->gid,
	       &group->members);
	return group;
}

static void group_destroy(Group group)
{
	free(group->name);
	free(group->members);
	return;
}

static void iterate_directory(const char *path,
			      void (*callback)(const char *path))
{
	DIR *root = opendir(path);
	check(root,return,"Cannot open directory %s",path);

	chdir(path);
	for (struct dirent *dir = readdir(root);dir;dir = readdir(root)) {
		if (dir->d_name[0] == '.')
			continue;

		callback(dir->d_name);
	}

	closedir(root);
	chdir("..");
	return;
}

int main()
{
	gLogStream = stderr;
	return 0;
}
