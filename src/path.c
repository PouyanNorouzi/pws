#include "path.h"

#include <dirent.h>
#include <errno.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "dynamic_str.h"
#include "pssh.h"
#ifdef _WIN32
#  include <direct.h>
#  define mkdir(x, y) _mkdir(x)
#endif

const char* SEPERATOR[] = {"\\", "/"};

Path path_init(const char* path, enum platform platform) {
    Path new_path;

    new_path = (Path)malloc(sizeof(struct path));
    if(new_path == NULL) {
        fprintf(stderr, "failed to allocate memory for new path\n");
        return NULL;
    }

    new_path->path = dynamic_str_init(path);
    if(new_path->path == NULL) {
        fprintf(stderr, "failed to initialize dynamic string\n");
        free(new_path);
        return NULL;
    }

    new_path->platform = platform;

    return new_path;
}

Path path_duplicate(Path path) {
    return path_init(path->path->str, path->platform);
}

int path_prev(Path path) {
    DynamicStr  pathstr;
    int         i;
    const char* seperator = SEPERATOR[path->platform];

    if(path == NULL || path->path->size == 1) {
        fprintf(stderr, "pwd cannot be null or empty\n");
        return PATH_ERROR;
    }

    i       = path->path->size;
    pathstr = path->path;

    if(strcmp(pathstr->str, seperator) == 0) {
        fprintf(stderr, "cannot move to before the root directory");
        return PATH_ERROR;
    }

    i--;
    while(i > 0 && pathstr->str[i] != seperator[0]) {
        i--;
    }

    i = (i == 0) ? 1 : i;

    dynamic_str_remove(pathstr, i);

    return PATH_OK;
}

int path_go_into(Path path, char* s) {
    DynamicStr  pathstr;
    int         rc;
    const char* seperator = SEPERATOR[path->platform];

    if(path == NULL || s == NULL) {
        fprintf(stderr, "pwd or node or cannot be null\n");
        return PATH_ERROR;
    }

    pathstr = path->path;

    // if the array is just '/' and '\0' we are at root directory
    if(pathstr->size != 2) {
        rc = dynamic_str_cat(pathstr, seperator);
        if(rc != DYNAMIC_STR_OK) {
            fprintf(stderr, "error concaconating pwd\n");
            return PATH_ERROR;
        }
    }

    rc = dynamic_str_cat(pathstr, s);
    if(rc != DYNAMIC_STR_OK) {
        fprintf(stderr, "error concaconating pwd\n");
        return PATH_ERROR;
    }

    return PATH_OK;
}

char* path_get_curr(Path path) {
    char*       filename;
    DynamicStr  pathstr = path->path;
    int         i;
    const char* seperator = SEPERATOR[path->platform];

    i = strlen(pathstr->str) - 1;
    while(i > 0 && pathstr->str[i] != seperator[0]) {
        i--;
    }

    filename = (char*)malloc(sizeof(char) * (strlen(pathstr->str) - i));

    strcpy(filename, pathstr->str + i + 1);

    return filename;
}

Path path_get_downloads_directory(void) {
    Path new_path;

    new_path = path_init(HOME_DIRECTORY, CURR_PLATFORM);
    path_go_into(new_path, "Downloads");

    return new_path;
}

unsigned long long path_get_file_size(Path path) {
    struct stat path_stat;
    int         rc;

    rc = stat(path->path->str, &path_stat);
    if(rc != 0) {
        fprintf(stderr, "failed to get the stat of the path: %d\n", errno);
        return 0;
    }

    if(!S_ISREG(path_stat.st_mode)) {
        fprintf(stderr, "the path is not a regular file\n");
        return 0;
    }

    return (unsigned long long)path_stat.st_size;
}

bool path_is_directory(Path path) {
    struct stat path_stat;
    int         rc;

    rc = stat(path->path->str, &path_stat);
    if(rc != 0) {
        fprintf(stderr, "failed to get the statof the path: %d\n", errno);
        return false;
    }

    if(S_ISDIR(path_stat.st_mode)) {
        return true;
    }
    return false;
}

bool path_is_file(Path path) {
    struct stat path_stat;
    int         rc;

    rc = stat(path->path->str, &path_stat);
    if(rc != 0) {
        fprintf(stderr, "failed to get the statof the path: %d\n", errno);
        return false;
    }

    if(S_ISREG(path_stat.st_mode)) {
        return true;
    }
    return false;
}

bool path_exists(Path path) {
    struct stat path_stat;

    errno  = 0;
    int rc = stat(path->path->str, &path_stat);
    if(rc == -1) {
        if(errno == 2) {
            return false;
        } else {
            fprintf(stderr,
                    "There was an error running stat on %s: %d\n",
                    path->path->str,
                    errno);
            return false;
        }
    }

    return true;
}

DIR* path_opendir(Path path) { return opendir(path->path->str); }

FILE* path_fopen(Path path, const char* modes) {
    char buffer[BUFFER_SIZE];

    if(modes[0] == 'w' && path_exists(path)) {
        printf("File %s already exists override?[y/N]", path->path->str);
        pfgets(buffer, BUFFER_SIZE);

        if(buffer[0] != 'Y' && buffer[0] != 'y') return NULL;
    }

    return fopen(path->path->str, modes);
}

int path_create_directory(Path path) {
    int  rc;
    char buffer[BUFFER_SIZE];

    errno = 0;

    rc = mkdir(path->path->str, 0775);
    if(rc == -1 && errno == 17) {
        printf("Directory %s already exists override?[y/N]: ", path->path->str);
        pfgets(buffer, BUFFER_SIZE);
        if(buffer[0] == 'y' || buffer[0] == 'Y') {
            rc = path_rm_directory(path);
            if(rc == -1) return rc;

            rc = mkdir(path->path->str, 0775);
        }
    } else if(rc == -1) {
        fprintf(stderr, "%d\n", errno);
    }

    return rc;
}

int path_rm_directory(Path path) {
    int rc;

    rc = remove(path->path->str);
    if(rc == -1) {
        fprintf(stderr, "Error deleting %s: %d\n", path->path->str, errno);
    }

    return 1;
}

sftp_file path_sftp_open(Path path) { }

int path_free(Path path) {
    dynamic_str_free(path->path);
    free(path);
    return PATH_OK;
}
