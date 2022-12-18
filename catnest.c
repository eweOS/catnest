/*
 *	catnest
 *	A substitution for systemd-sysusers
 *	Date:2022.12.17
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

// The least free ID
static uid_t gMinId = INT_MAX;

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
	char *name,*passwd,*members;
	gid_t gid;
} Group;

static gid_t gMinGid = INT_MAX;

/*
 *	groupname:password:gid:userlist
 */
static inline Group next_group(FILE *groupFile)
{
	Group group = {};
	char *gid;
	char **content[4] = {&group.name,&group.passwd,&gid,&group.members};
	for (int i = 0;i < 4;i++) {
		fscanf(groupFile,"%m[^:\n]",content[i]);
		fgetc(groupFile);
	}
	group.gid = atoi(option(gid));
	free_if(1,gid);
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
	memset(gGroupList + gGroupListSize,0,sizeof(Group) * 128);
	gGroupListSize += 128;
	return;
}

static void load_group(FILE *file)
{
	gGroupNum = 0;
	do {
		extend_group();
		gGroupList[gGroupNum] = next_group(file);
		gGroupNum++;
	} while(gGroupList[gGroupNum - 1].name);
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

static int get_group_by_name(const char *name)
{
	for (int i = 0;i < gGroupNum;i++) {
		if (!strcmp(gGroupList[i].name,name))
			return i;
	}
	return gGroupNum;
}

static int get_group_by_id(gid_t id)
{
	for (int i = 0;i < gGroupNum;i++) {
		if (gGroupList[i].gid == id)
			return i;
	}
	return gGroupNum;
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
			gid_t gid = gMinId;
			gMinId++;
			if (id) {
				char *end = NULL;
				gid_t t = (int)strtol(id,&end,10);
				if (!*end) {
					gid = t;
					gMinId = t + 1;
				}
			}

			check(get_group_by_name(name) == gGroupNum &&
			      get_group_by_id(gid)    == gGroupNum,
			      goto nextLoop,
			      "Duplicated group %s\n",name);


			extend_group();
			gGroupList[gGroupNum] = (Group) {
						.name	= strdup(name),
						.passwd	= strdup(""),
						.gid	= gid,
					};

			gGroupNum++;
		} else if (type == 'r') {
			uid_t lowest = 0,highest = 0;
			check(sscanf(id,"%u%u",&lowest,&highest) != 2,
			      goto nextLoop,
			      "Invalid ID range %s",id);
			gMinId = gMinId < lowest ? lowest : gMinId;
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
		gMinId = gMinId > user.pw_uid ? user.pw_uid : gMinId;
		passwd_destroy(user);
	}
	gMinId = gMinId == INT_MAX ? 0 : gMinId;
	fclose(passwd);

	for (int i = 0;i < gGroupNum;i++) {
		gMinGid = gMinId > gGroupList[i].gid ?
				gGroupList[i].gid : gMinId;
	}
	gMinId = gMinId == INT_MAX ? 0 : gMinId;

	passwd = fopen(CONF_PATH_PASSWD,"a");
	check(passwd,return -1,"Cannot open passwd file %s\n",CONF_PATH_PASSWD);
	parse_conf(argv[1],passwd);

	group = fopen(CONF_PATH_GROUP,"w");
	write_group(group);
	fclose(group);
	return 0;
}
