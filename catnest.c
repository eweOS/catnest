/*
 *	catnest
 *	A substitution for systemd-sysusers
 *	Date:2023.01.30
 *	File:/catnest.c
 *	By MIT License.
 *	Copyright (c) 2022-2023 Ziyao.
 *	This program is a part of eweOS Project.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include<assert.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<stdarg.h>
#include<limits.h>
#include<stdbool.h>
#include<stdint.h>
#include<time.h>

#include<sys/types.h>
#include<unistd.h>
#include<pwd.h>
#include<dirent.h>

#define CONF_PATH_PASSWD	"/etc/passwd"
#define CONF_PATH_GROUP		"/etc/group"
#define CONF_PATH_SHADOW	"/etc/shadow"
#define CONF_PATH_GSHADOW	"/etc/gshadow"

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

int *gIdUsed,gLastId;
size_t gFreeId;
static void id_init()
{
	gIdUsed = malloc(sizeof(int) * (1 << 16));
	assert(gIdUsed);
	memset(gIdUsed,0,sizeof(int) * (1 << 16));
	return;
}

static int id_get()
{
	for (int i = gLastId;i < (1 << 16);i++) {
		if (!gIdUsed[i]) {
			gLastId = i ? i - 1 : i;
			return i;
		}
	}
	abort();
}

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
	     i < sizeof(content) / sizeof(char **);
	     i++) {
		fscanf(passwd,"%m[^\n:]",content[i]);
		fgetc(passwd);		// Skip the colon
		if (feof(passwd))
			return (struct passwd) {
						.pw_name = NULL,
					       };
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
		passwd_destroy(user);
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
		passwd_destroy(user);
		user = next_user(passwd);
	}
	return user;
}

typedef struct {
	char *name,*passwd,*members;
	gid_t gid;
} Group;


/*
 *	groupname:password:gid:userlist
 */
static inline Group next_group(FILE *groupFile)
{
	Group group = { .name = NULL };
	char *gid = NULL;
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

static void write_group(FILE *file,FILE *gshadow)
{
	for (int i = 0;i < gGroupNum;i++) {
		fprintf(file,"%s:%s:%u:%s\n",gGroupList[i].name,
					     option(gGroupList[i].passwd),
					     gGroupList[i].gid,
					     option(gGroupList[i].members));
		fprintf(gshadow,"%s:*::%s\n",gGroupList[i].name,
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
	gid_t gid = id_get();
	if (id) {
		char *end = NULL;
		gid_t t = (int)strtol(id,&end,10);
		if (!*end) {
			gid = t;
			gIdUsed[t] = 1;
		} else {
			gIdUsed[gid] = 1;
		}
	} else {
		gIdUsed[gid] = 1;
	}

	if (get_group_by_name(name) != gGroupNum)
	      return;
	check(get_group_by_id(gid) == gGroupNum,return,
	      "Duplicated GID %d for group %s\n",gid,name);


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
			    const char *gecos,const char *home,const char *shell,
			    FILE *shadow)
{
	char *groupIdStr = NULL;
	uid_t uid = strtol(id,&groupIdStr,10);

	struct passwd tmp = get_user_by_name(passwd,name);
	if (tmp.pw_name)
		return;
	passwd_destroy(tmp);
	if (id && *id != '-') {
		tmp = get_user_by_uid(passwd,uid);
		check(!tmp.pw_name,return,"Duplicated user %s\n",name);
		passwd_destroy(tmp);
	}

	gid_t gid;
	/*	Case 1: The group's id is specified	*/
	if (*groupIdStr == ':') {
		groupIdStr++;	// Skip the colon
		int groupIndex = get_group_by_id(atol(groupIdStr));
		check(groupIndex < gGroupNum,return;,
		      "Group with GID %s doesn't exist\n",groupIdStr);
		gid = atol(groupIdStr);
	} else {
	/*	Case 2: Create group with the same name as the user  */
		if (*groupIdStr == '-')
			uid = id_get();	// will be increased in add_group()

		int groupIndex = get_group_by_name(name);
		if (groupIndex != gGroupNum) {
			gid = gGroupList[groupIndex].gid;	// won't add a new group
			gIdUsed[uid] = 1;
		} else {
			add_group(name,NULL);
			gid = gGroupList[get_group_by_name(name)].gid;
		}
	}

	fprintf(passwd,"%s:x:%u:%u:%s:%s:%s\n",name,uid,gid,gecos,
		home ? home : "/",shell ? shell :
				  uid ? "/usr/sbin/nologin" : "/bin/sh");
	fprintf(shadow,"%s:*:%lu:0:7:99999:::\n",name,
		time(NULL) / (60 * 60 * 24));
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

	do {
		free(line);
		size = 0;
		line = NULL;
		size = getline(&line,(size_t*)&size,conf);
	} while (size > 0 && (*line == '#' || *line == '\n'));

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

typedef struct {
	FILE *passwd,*shadow;
} Parse_Conf_Arg;
static void parse_conf(const char *path,void *in)
{
	Parse_Conf_Arg *arg = in;
	FILE *passwd = arg->passwd;
	FILE *shadow = arg->shadow;
	FILE *conf = fopen(path,"r");
	check(conf,return,"Cannot open configuration %s\n",path);

	// Type Name ID GECOS Home Shell
	char type,*name = NULL,*id = NULL,*gecos = NULL;
	char *home = NULL,*shell = NULL;
	for (int num = read_conf(conf,&type,&name,&id,&gecos,&home,&shell);
	     num != -1;
	     num = read_conf(conf,&type,&name,&id,&gecos,&home,&shell)){
		if (type == 'g') {
			add_group(name,id);
		} else if (type == 'u') {
			 add_user(passwd,name,id,gecos,home,shell,shadow);
		} else if (type == 'r') {
			// Ignore
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

	id_init();
	FILE *passwd = fopen(CONF_PATH_PASSWD,"r");
	check(passwd,return -1,"Cannot open passwd file %s\n",CONF_PATH_PASSWD);
	for (struct passwd user = next_user(passwd);
	     user.pw_name;
	     user = next_user(passwd)) {
		gIdUsed[user.pw_uid] = 1;
		passwd_destroy(user);
	}
	fclose(passwd);

	for (int i = 0;i < gGroupNum;i++)
		gIdUsed[gGroupList[i].gid] = 1;

	passwd = fopen(CONF_PATH_PASSWD,"a+");
	check(passwd,return -1,"Cannot open passwd file %s\n",CONF_PATH_PASSWD);

	FILE *shadow = fopen(CONF_PATH_SHADOW,"a+");
	check(shadow,return -1,"Cannot open shadow file %s\n",
	      CONF_PATH_SHADOW);

	Parse_Conf_Arg arg = {
				.passwd	= passwd,
				.shadow	= shadow,
			     };
	int isConfSpecified = 0;
	for (int i = 1;i < argc;i++) {
		if (!strcmp(argv[i],"--help")) {
			print_help(argv[0]);
		} else {
			parse_conf(argv[i],(void*)&arg);
			isConfSpecified = 1;
		}
	}

	if (!isConfSpecified) {
		iterate_directory("/etc/sysusers.d",parse_conf,(void*)&arg);
		iterate_directory("/usr/lib/sysusers.d",parse_conf,(void*)&arg);
	}

	group = fopen(CONF_PATH_GROUP,"w");
	FILE *gshadow = fopen(CONF_PATH_GSHADOW,"w");
	check(gshadow,return -1,"Cannot open gshadow file %s\n",
	      CONF_PATH_GSHADOW);
	write_group(group,gshadow);
	fclose(group);
	fclose(passwd);
	fclose(shadow);
	fclose(gshadow);
	return 0;
}
