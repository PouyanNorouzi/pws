#ifndef DYNAMIC_STR_H
#define DYNAMIC_STR_H

#define DYNAMIC_STR_ERROR 0
#define DYNAMIC_STR_OK 1

struct dynamic_str {
    char* str;
    int size;
};

typedef struct dynamic_str* DynamicStr;

DynamicStr dynamic_str_init(const char* str);

int dynamic_str_cat(DynamicStr dest, char* src);

int dynamic_str_change(DynamicStr dest, char* src);

int dynamic_str_remove(DynamicStr str, int from);

int dynamic_str_free(DynamicStr str);

#endif //DYNAMIC_STR_H