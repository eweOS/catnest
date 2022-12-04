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
#include<limits.h>

#include<sys/types.h>
#include<unistd.h>
#include<pwd.h>
#include<dirent.h>

#define CONF_PATH_PASSWD	"./passwd"
#define CONF_PATH_GROUP		"./group"

static FILE *gLogStream = NULL;
#define check(assertion,action,...) do {				\
	if (!(assertion)) {						\
		fprintf(gLogStream,__VA_ARGS__);			\
		action;							\
	} } while(0)
#define log(fmt,...) fprintf(gLogStream,fmt,__VA_ARGS__)

#define option(x) ((x) ? (x) : "")

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

static uid_t gMinUid = INT_MAX;

/*
 *	name:password:uid:gid:comment:home:shell
 */
static inline struct passwd next_user(FILE *passwd)
{
	struct passwd user;
	fscanf(passwd,"%ms:%ms:%d:%d:%ms:%ms:%ms",&user.pw_name,
	       &user.pw_passwd,&user.pw_uid,&user.pw_gid,&user.pw_gecos,
	       &user.pw_dir,&user.pw_shell);
	return user;
}

static inline void passwd_destroy(struct passwd user)
{
	free(user.pw_name);
	free(user.pw_passwd);
	free(user.pw_gecos);
	free(user.pw_dir);
	free(user.pw_shell);
	return;
}

static struct passwd get_user_by_uid(FILE *passwd,uid_t uid)
{
	struct passwd user = next_user(passwd);
	while (!feof(passwd)) {
		if (user.pw_uid == uid)
			break;
		user = next_user(passwd);
	}

	rewind(passwd);
	return user;
}

static struct passwd get_user_by_name(FILE *passwd,const char *name)
{
	struct passwd user = next_user(passwd);
	while (!feof(passwd)) {
		if (!strcmp(user.pw_name,name))
			break;

		user = next_user(passwd);
	}

	rewind(passwd);
	return user;
}

typedef struct {
	char *name,*passwd;
	gid_t gid;
	char *members;
} Group;

static gid_t gMinGid = INT_MAX;

/*
 *	groupname:password:gid:userlist
 */
static inline Group next_group(FILE *groupFile)
{
	Group group;
	fscanf(groupFile,"%ms:%ms:%d:%ms",&group.name,&group.passwd,
	       &group.gid,&group.members);
	return group;
}

static void group_destroy(Group group)
{
	free(group.name);
	free(group.members);
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

	gGroupList = realloc(gGroupList,
			     sizeof(Group) * (gGroupListSize + 128));
	check(gGroupList,exit(-1),"Cannot allocate memory");
	gGroupListSize += 128;
	return;
}

static void load_group(FILE *file)
{
	for (gGroupNum = 0,gGroupListSize = 0;!feof(file);gGroupNum++) {
		extend_group();
		gGroupList[gGroupNum] = next_group(file);
	}
	gGroupNum--;
	return;
}

static void write_group(FILE *file)
{
	for (int i = 0;i < gGroupNum;i++) {
		fprintf(file,"%s:%s:%u:%s\n",gGroupList[i].name,
					     option(gGroupList[i].passwd),
					     gGroupList[i].gid,
					     option(gGroupList[i].members));
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

static void next_line(FILE *file)
{
	for (int c = fgetc(file);c != EOF && c !='\n';c = fgetc(file));
	return;
}

static void parse_conf(const char *path,FILE *passwd)
{
	FILE *conf = fopen(path,"r");
	check(conf,return,"Cannot open configuration %s\n",path);

	// Type Name ID GECOS Home Shell
	static const char *pattern = "%c %ms %ms \"%m[^\"]s\" %ms %ms";
	char type,*name = NULL,*id = NULL,*gecos = NULL;
	char *home = NULL,*shell = NULL;
	for (int num = fscanf(conf,pattern,&type,&name,&id,&gecos,&home,&shell);
	     num != EOF;
	     num = fscanf(conf,pattern,&type,&name,&id,&gecos,&home,&shell)) {
		printf("type %c, name %s\n",type,name);
		if (type == '#') {
			next_line(conf);
			goto nextLoop;
		} else if (type == 'g') {
			char *end = NULL;
			int gid = (int)strtol(id,&end,10);
			gid = *end ? gMinGid : gid;

			extend_group();
			gGroupList[gGroupNum] = (Group) {
						.name	= strdup(name),
						.passwd	= strdup(""),
						.gid	= gid,
					};

			gGroupNum++;
		} else {
			log("Unknow type %c\n",type);
			goto nextLoop;
		}


nextLoop:
		free_if(5,name,id,gecos,home,shell);
		name = id = gecos = home = shell = NULL;
	}

	fclose(conf);

	return;
}

int main(int argc,const char *argv[])
{
	gLogStream = stderr;
	check(argc == 2,return -1,"Need configuration\n");

	FILE *group = fopen(CONF_PATH_GROUP,"r+");
	check(group,return -1,"Cannot open group file %s\n",CONF_PATH_GROUP);
	load_group(group);

	FILE *passwd = fopen(CONF_PATH_PASSWD,"r");
	check(passwd,return -1,"Cannot open passwd file %s\n",CONF_PATH_PASSWD);
	for (struct passwd user = next_user(passwd);
	     user.pw_name;
	     user = next_user(passwd)) {
		gMinUid = gMinUid > user.pw_uid ? user.pw_uid : gMinUid;
		passwd_destroy(user);
	}
	gMinUid = gMinUid == INT_MAX ? 0 : gMinUid;
	fclose(passwd);

	for (int i = 0;i < gGroupNum;i++) {
		gMinGid = gMinGid > gGroupList[i].gid ?
				gGroupList[i].gid : gMinGid;
	}
	gMinGid = gMinGid == INT_MAX ? 0 : gMinGid;

	passwd = fopen(CONF_PATH_PASSWD,"a");
	check(passwd,return -1,"Cannot open passwd file %s\n",CONF_PATH_PASSWD);
	parse_conf(argv[1],passwd);

	group = fopen(CONF_PATH_GROUP,"w");
	write_group(group);
	fclose(group);
	return 0;
}
