#include "dynamic_str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DynamicStr dynamic_str_init(const char* str) {
    if(str == NULL) {
        fprintf(stderr, "the initial string cannot be null\n");
        return NULL;
    }

    DynamicStr new_str = (DynamicStr)malloc(sizeof(struct dynamic_str));
    if(new_str == NULL) {
        fprintf(stderr, "failed to allocate memory to a DynamicStr\n");
        return NULL;
    }

    new_str->str = (char*)malloc(sizeof(char) * (strlen(str) + 1));
    if(new_str->str == NULL) {
        fprintf(
            stderr,
            "failed to allocate memory for the string inside the dynamic str\n");
        free(new_str);
        return NULL;
    }
    strcpy(new_str->str, str);
    new_str->size = strlen(str) + 1;

    return new_str;
}

int dynamic_str_cat(DynamicStr dest, const char* src) {
    if(dest == NULL || src == NULL) {
        fprintf(stderr,
                "destination or src cannot be null when concatinting\n");
        return DYNAMIC_STR_ERROR;
    }

    dest->str =
        (char*)realloc(dest->str, sizeof(char) * (dest->size + strlen(src)));
    if(dest->str == NULL) {
        fprintf(stderr,
                "error occured while reallcoating memory to dynamic string\n");
        return DYNAMIC_STR_ERROR;
    }
    dest->size = dest->size + strlen(src);

    strcat(dest->str, src);

    return DYNAMIC_STR_OK;
}

int dynamic_str_change(DynamicStr dest, char* src) {
    if(dest == NULL || src == NULL) {
        fprintf(stderr,
                "destination or src cannot be null when changing string\n");
        return DYNAMIC_STR_ERROR;
    }

    dest->str = (char*)realloc(dest->str, sizeof(char) * (strlen(src) + 1));
    if(dest->str == NULL) {
        fprintf(stderr,
                "error occured while reallcoating memory to dynamic string\n");
        return DYNAMIC_STR_ERROR;
    }
    dest->size = strlen(src) + 1;

    strcpy(dest->str, src);

    return DYNAMIC_STR_OK;
}

/**
 * removes all the chars after index (inclusive).
 */
int dynamic_str_remove(DynamicStr str, int index) {
    if(str == NULL) {
        fprintf(stderr, "dynamic string cannot be null\n");
        return DYNAMIC_STR_ERROR;
    }

    if(index < 0 || index > str->size - 1) {
        fprintf(stderr,
                "invalid index %d should be in range 0-%d\n",
                index,
                str->size - 1);
        return DYNAMIC_STR_ERROR;
    }

    str->str = (char*)realloc(str->str, index + 1);
    if(str->str == NULL) {
        fprintf(stderr, "failed to resize string when removing\n");
        return DYNAMIC_STR_ERROR;
    }

    str->str[index] = '\0';
    str->size       = index + 1;

    return DYNAMIC_STR_OK;
}

int dynamic_str_free(DynamicStr str) {
    free(str->str);
    free(str);
    return DYNAMIC_STR_OK;
}
