#include "path.h"
#include "dynamic_str.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef _WIN32
#include <sys/stat.h>
#else
#include <direct.h>
#endif

const char* SEPERATOR[] = { "\\", "/" };

Path path_init(const char* path, enum platform platform)
{
    Path new_path;

    new_path = (Path)malloc(sizeof(struct path));

    new_path->path = dynamic_str_init(path);
    new_path->platform = platform;

    return new_path;
}

Path path_duplicate(Path path)
{
    return path_init(path->path->str, path->platform);
}

int path_prev(Path path)
{
    DynamicStr pathstr = path->path;
    int i = path->path->size;
    const char* seperator = SEPERATOR[path->platform];

    if(path == NULL || i == 1)
    {
        fprintf(stderr, "pwd cannot be null or empty\n");
        return PATH_ERROR;
    }

    if(strcmp(pathstr->str, seperator) == 0)
    {
        fprintf(stderr, "cannot move to before the root directory");
        return PATH_ERROR;
    }

    i--;
    while(i > 0 && pathstr->str[i] != seperator[0])
        i--;

    i = (i == 0) ? 1 : i;

    dynamic_str_remove(pathstr, i);

    return PATH_OK;
}

int path_go_into(Path path, char* s)
{
    DynamicStr pathstr;
    int rc;
    const char* seperator = SEPERATOR[path->platform];

    if(path == NULL || s == NULL)
    {
        fprintf(stderr, "pwd or node or cannot be null\n");
        return PATH_ERROR;
    }

    pathstr = path->path;

    // if the array is just '/' and '\0' we are at root directory
    if(pathstr->size != 2)
    {
        rc = dynamic_str_cat(pathstr, seperator);
        if(rc != DYNAMIC_STR_OK)
        {
            fprintf(stderr, "error concaconating pwd\n");
            return PATH_ERROR;
        }
    }

    rc = dynamic_str_cat(pathstr, s);
    if(rc != DYNAMIC_STR_OK)
    {
        fprintf(stderr, "error concaconating pwd\n");
        return PATH_ERROR;
    }

    return PATH_OK;
}

char* path_get_curr(Path path)
{
    char* filename;
    DynamicStr pathstr = path->path;
    int i;
    const char* seperator = SEPERATOR[path->platform];

    i = strlen(pathstr->str) - 1;
    while(i > 0 && pathstr->str[i] != seperator[0])
        i--;

    filename = (char*)malloc(sizeof(char) * (strlen(pathstr->str) - i));

    strcpy(filename, pathstr->str + i + 1);

    return filename;
}

Path path_get_downloads_directory(void)
{
    Path new_path;

    new_path = path_init(HOME_DIRECTORY, CURR_PLATFORM);
    path_go_into(new_path, "Downloads");

    return new_path;
}

int path_create_directory(Path path)
{
#ifdef _WIN32
    return _mkdir(path->path->str);
#else
    return mkdir(path->path->str, 0775);
#endif
}

int path_free(Path path)
{
    dynamic_str_free(path->path);
    free(path);
    return PATH_OK;
}