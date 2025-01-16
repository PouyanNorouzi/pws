#ifndef PATH_H
#define PATH_H

#include <dynamic_str.h>
#include <stdlib.h>

#define PATH_OK 1
#define PATH_ERROR 0

#ifndef _WIN32
#define HOME_DIRECTORY (getenv("HOME"))
#define CURR_PLATFORM PLATFORM_LINUX
#else
//Windows code
#endif

enum platform {
    PLATFORM_WINDOWS,
    PLATFORM_LINUX
};

struct path {
    DynamicStr path;
    enum platform platform;
};

typedef struct path* Path;

Path path_init(const char* path, enum platform platform);

Path path_duplicate(Path path);

int path_prev(Path path);

int path_go_into(Path path, char* s);

char* path_get_curr(Path path);

Path path_get_downloads_directory(void);

int path_create_directory(Path path);

int path_free(Path path);

#endif // PATH_H