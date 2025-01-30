#ifndef PATH_H
#define PATH_H

#include <dirent.h>
#include <libssh/sftp.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>

#include "dynamic_str.h"

#define PATH_OK    1
#define PATH_ERROR 0

#ifndef _WIN32
#  define HOME_DIRECTORY (getenv("HOME"))
#  define CURR_PLATFORM  PLATFORM_LINUX
#  define PATH_SEPERATOR "/"
#else
#  define HOME_DIRECTORY (getenv("USERPROFILE"))
#  define CURR_PLATFORM  PLATFORM_WINDOWS
#  define PATH_SEPERATOR "\\"
#endif

enum platform { PLATFORM_WINDOWS, PLATFORM_LINUX };

struct path {
    DynamicStr    path;
    enum platform platform;
};

typedef struct path* Path;

Path path_init(const char* path, enum platform platform);

Path path_duplicate(Path path);

int path_prev(Path path);

int path_go_into(Path path, char* s);

char* path_get_curr(Path path);

Path path_get_downloads_directory(void);

unsigned long long path_get_file_size(Path path);

bool path_is_directory(Path path);

bool path_is_file(Path path);

bool path_exists(Path path);

DIR* path_opendir(Path path);

FILE* path_fopen(Path path, const char* modes);

int path_rm_directory(Path path);

int path_create_directory(Path path);

sftp_file path_sftp_open(Path path);

int path_free(Path path);

#endif  // PATH_H
