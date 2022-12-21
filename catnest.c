/*
 *	catnest
 *	A substitution for systemd-sysusers
 *	Date:2022.12.21
 *	File:/catnest.c
 *	By MIT License.
 *	Copyright (c) 2022 Ziyao.
 *	This program is a part of eweOS Project.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

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
	struct passwd user = { .pw_name = NULL };
	char *strUid = NULL,*strGid = NULL;
	char **content[] = { &user.pw_name,&user.pw_passwd,&strUid,
			     &strGid,&user.pw_gecos,&user.pw_dir,
			     &user.pw_shell };
	for (unsigned int i = 0;
	     !feof(passwd) && i < sizeof(content) / sizeof(char **);
	     i++) {
		fscanf(passwd,"%m[^\n]",content[i]);
		fgetc(passwd);		// Skip the colon
	}

	user.pw_uid = atol(option(strUid));
	user.pw_gid = atol(option(strGid));
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
	rewind(passwd);
	struct passwd user = next_user(passwd);
	while (user.pw_name) {
		if (user.pw_uid == uid)
			break;
		user = next_user(passwd);
	}
	return user;
}

static struct passwd get_user_by_name(FILE *passwd,const char *name)
{
	rewind(passwd);
	struct passwd user = next_user(passwd);
	while (user.pw_name) {
		if (!strcmp(user.pw_name,name))
			break;

		user = next_user(passwd);
	}
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
	Group group = { .name = NULL };
	char *gid;
	char **content[4] = {&group.name,&group.passwd,&gid,&group.members};
	for (int i = 0;i < 4;i++) {
		fscanf(groupFile,"%m[^:\n]",content[i]);
		fgetc(groupFile);
	}
	group.gid = atol(option(gid));
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
			      void (*callback)(const char *path,void *ctx),
			      void *ctx)
{
	DIR *root = opendir(path);
	check(root,return,"Cannot open directory %s\n",path);

	chdir(path);
	for (struct dirent *dir = readdir(root);dir;dir = readdir(root)) {
		if (dir->d_name[0] == '.')
			continue;

		callback(dir->d_name,ctx);
	}

	closedir(root);
	chdir("..");
	return;
}

static void add_group(const char *name,const char *id)
{
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
	      return,
	      "Duplicated group %s\n",name);


	extend_group();
	gGroupList[gGroupNum] = (Group) {
				.name	= strdup(name),
				.passwd	= strdup(""),
				.gid	= gid,
			};

	gGroupNum++;

	return;
}

static inline void add_user_to_group(int groupIndex,uid_t uid)
{
	char *oldStr = gGroupList[groupIndex].members;

	asprintf(&gGroupList[groupIndex].members,"%s,%u",oldStr,uid);
	check(gGroupList[groupIndex].members,exit(-1),
	      "Cannot allocate memory for group member list");

	if (oldStr)
		free(oldStr);

	return;
}

static inline void add_user(FILE *passwd,const char *name,const char *id,
			    const char *gecos,const char *home,const char *shell)
{
	char *groupIdStr = NULL;
	uid_t uid = strtol(id,&groupIdStr,10);

	struct passwd tmp1 = get_user_by_name(passwd,name);
	struct passwd tmp2 = get_user_by_uid(passwd,uid);
	check(!tmp1.pw_name && !tmp2.pw_name,return,
	      "Duplicated user %s\n",name);
	passwd_destroy(tmp1);
	passwd_destroy(tmp2);

	gid_t gid;
	/*	Case 1: The group's id is specified	*/
	if (*groupIdStr == ':') {
		int groupIndex = get_group_by_id(atol(groupIdStr));
		check(groupIndex < gGroupNum,return;,
		      "Group with GID %s doesn't exist\n",groupIdStr);
		gid = atol(groupIdStr);
	} else {
	/*	Case 2: Create group with the same name as the user  */
		if (*groupIdStr == '-')
			uid = gMinId;	// will be increased in add_group()

		int groupIndex = get_group_by_name(name);
		if (groupIndex != gGroupNum) {
			gid = gGroupList[groupIndex].gid;
			uid++;		// won't add a new group
		} else {
			add_group(name,NULL);
			gid = gGroupList[get_group_by_name(name)].gid;
		}
	}

	fprintf(passwd,"%s::%u:%u:%s:%s:%s\n",name,uid,gid,gecos,
		home ? home : "/",shell ? shell :
				  uid ? "/usr/sbin/nologin" : "/bin/sh");
	return;
}

static void fskip_space(FILE *file)
{
	int c = fgetc(file);
	while (c != EOF && isspace(c))
		c = fgetc(file);
	ungetc(c,file);
	return;
}

static void next_line(FILE *file)
{
	for (int c = fgetc(file);c != EOF && c != '\n';c = fgetc(file));
	return;
}

static inline int read_conf(FILE *conf,char *type,char **name,char **id,
			    char **gecos,char **home,char **shell)
{
	int ret;
	/*	Skip comment	*/
	fskip_space(conf);
	char *line = NULL;
	ssize_t size = 0;
	for (size = getline(&line,(size_t*)&size,conf);
	     size > 0 && *line == '#';
	     size = getline(&line,(size_t*)&size,conf)) {
		free(line);
		size = 0;
	}

	if (size < 0) {
		ret = -1;
		goto end;
	}

	// Now line holding a valid configuration line
	static const char *pattern = "%c %ms %ms \"%m[^\"]\" %ms %ms";
	ret = sscanf(line,pattern,type,name,id,gecos,home,shell);
end:
	free(line);
	return ret;
}

static void parse_conf(const char *path,FILE *passwd)
{
	FILE *conf = fopen(path,"r");
	check(conf,return,"Cannot open configuration %s\n",path);

	// Type Name ID GECOS Home Shell
	char type,*name = NULL,*id = NULL,*gecos = NULL;
	char *home = NULL,*shell = NULL;
	for (int num = read_conf(conf,&type,&name,&id,&gecos,&home,&shell);
	     num != -1;
	     num = read_conf(conf,&type,&name,&id,&gecos,&home,&shell)){
		printf("type %c, name %s\n",type,name);
		if (type == 'g') {
			add_group(name,id);
		} else if (type == 'u') {
			 add_user(passwd,name,id,gecos,home,shell);
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

static void print_help(const char *name)
{
	fputs("\t\tcatnest\n",stderr);
	fputs("A substitution for systemd-sysusers\n",stderr);
	fprintf(stderr,"Usage: %s [OPTIONS] [CONFIGURATION]\n",name);
	fputs("Options:\n\t--help\t\tDisplay this help\n",stderr);
	fputs("This program is part of eweOS project,",stderr);
	fputs("distributed under MIT License.\n",stderr);
	fputs("See https://os.ewe.moe for details\n",stderr);
	exit(-1);
	return;
}

int main(int argc,const char *argv[])
{
	gLogStream = stderr;

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

	passwd = fopen(CONF_PATH_PASSWD,"a+");
	check(passwd,return -1,"Cannot open passwd file %s\n",CONF_PATH_PASSWD);

	for (int i = 1;i < argc;i++) {
		if (!strcmp(argv[i],"--help")) {
			print_help(argv[0]);
		} else {
			parse_conf(argv[i],passwd);
		}
	}
	iterate_directory("/etc/sysusers.d",parse_conf,passwd);
	iterate_directory("/usr/lib/sysusers.d",parse_conf,passwd);

	group = fopen(CONF_PATH_GROUP,"w");
	write_group(group);
	fclose(group);
	fclose(passwd);
	return 0;
}
