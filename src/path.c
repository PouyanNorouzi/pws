#include "path.h"
#include "dynamic_str.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

Path path_init(const char* path)
{
    return dynamic_str_init(path);
}

int path_prev(Path path)
{
    int i = path->size;

    if(path == NULL || i == 1)
    {
        fprintf(stderr, "pwd cannot be null or empty\n");
        return PATH_ERROR;
    }

    if(strcmp(path->str, "/") == 0)
    {
        fprintf(stderr, "cannot move to before the root directory");
        return PATH_ERROR;
    }

    i--;
    while(i > 0 && path->str[i] != '/')
        i--;

    i = (i == 0) ? 1 : i;

    dynamic_str_remove(path, i);

    return PATH_OK;
}

int path_go_into(Path path, char* s)
{
    int rc;

    if(path == NULL || s == NULL)
    {
        fprintf(stderr, "pwd or node or cannot be null\n");
        return PATH_ERROR;
    }

    // if the array is just '/' and '\0' we are at root directory
    if(path->size != 2)
    {
        rc = dynamic_str_cat(path, "/");
        if(rc != DYNAMIC_STR_OK)
        {
            fprintf(stderr, "error concaconating pwd\n");
            return PATH_ERROR;
        }
    }

    rc = dynamic_str_cat(path, s);
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
    int i = strlen(path->str) - 1;

    while(i > 0 && path->str[i] != '/')
        i--;

    filename = (char*)malloc(sizeof(char) * (strlen(path->str) - i));

    strcpy(filename, path->str + i + 1);

    return filename;
}

int path_free(Path path)
{
    return dynamic_str_free(path);
}