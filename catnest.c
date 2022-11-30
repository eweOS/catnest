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
#include<ctype.h>
#include<stdarg.h>

#include<unistd.h>

#define CONF_PATH_PASSWD	"./passwd"
#define CONF_PATH_GROUP		"./group"

static FILE *gLogStream = NULL;
#define check(assertion,action,...) do {				\
	if (!(assertion)) {						\
		fprintf(gLogStream,__VA_ARGS__)				\
		action;							\
	} } while(0)

static void free_if(int num,...)
{
	va_list list;
	va_start(list,num);

	for (int i = 0;i < num;i++) {
		void *p = va_arg(list,void *);
		if (p)
			free(p);
	}
	va_end(list);

	return;
}

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
	char *name,*passwd;
	int gid;
	char *members;
} Group;

/*
 *	groupname:password:gid:userlist
 */
static inline Group next_group(FILE *groupFile)
{
	struct Group group;
	fscanf(groupFile,"%ms:%ms:%d:%ms",&group->name,&group->passwd,
	       &group->gid,&group->members);
	return group;
}

static void group_destroy(Group group)
{
	free(group->name);
	free(group->members);
	return;
}

/*
 *	We may modify the group file (unlike passwd, which is only appended.
 *	So load it into memory and write it back later
 */
static Group *gGroupList;
static int gGroupNum,gGroupListSize;
static void extend_group()
{
	if (gGroupNum < gGroupListSize)
		return;

	gGroupList = realloc(gGroupList,sizeof(Group) * (gGroupListSize + 128));
	check(gGroupList,exit(-1),"Cannot allocate memory");
	return;
}

static void load_group(FILE *file)
{
	for (gGroupNum = 0,gGroupListSize = 0;!feof(file);gGroupNum++) {
		extend_group();
		gGroupList[gGroupNum] = group_next(file);
	}
	return;
}

static void write_group(FILE *file)
{
	for (int i = 0;i < gGroupNum;i++) {
		fprintf("%s:%s:%d:%s\n",gGroupList[i]->name,
					gGroupList[i]->passwd,
					gGroupList[i]->gid,
					gGroupList[i]->members);
	}
	return;
}

static void iterate_directory(const char *path,
			      void (*callback)(const char *path))
{
	DIR *root = opendir(path);
	check(root,return,"Cannot open directory %s\n",path);

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

static const char *skip_space(const char *p)
{
	while (isspace(*p) && *p)
		p++;
	return p;
}

static void parse_conf(const char *path)
{
	FILE *conf = fopen(path,"r");
	check(conf,return,"Cannot open configuration %s\n",conf);

	// Type Name ID GECOS Home Shell
	static const char *pattern = "%c %ms %d \"%m[^\"]s\" %ms %ms";
	char type,*name,*gecos,*home,*shell;
	int id;
	for (int num = fscanf(conf,pattern,&type,&name,&id,&gecos,&home,&shell);
	     num != EOF;
	     num = fscanf(conf,pattern,&type,&name,&id,&gecos,&home,&shell)) {
		if (type == "#")
			goto nextLoop;

nextLoop:
		free_if(4,name,gecos,home,shell);
	}

	fclose(conf);

	return;
}

int main(int argc,const char *argv[])
{
	check(argc == 2,return -1,"Need configuration\n");

	gLogStream = stderr;
	FILE *group = fopen(CONF_PATH_GROUP,"r+");
	load_group();

	parse_conf(argv[1]);

	group = fopen(CONF_PATH_GROUP,"w");
	write_group();
	return 0;
}
