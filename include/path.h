#ifndef PATH_H
#define PATH_H

#include <dynamic_str.h>

#define PATH_OK 1
#define PATH_ERROR 0

typedef DynamicStr Path;

Path path_init(const char* path);

int path_prev(Path path);

int path_go_into(Path path, char* s);

char* path_get_curr(Path path);

int path_free(Path path);

#endif // PATH_H