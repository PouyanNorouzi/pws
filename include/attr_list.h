#ifndef ATTR_LIST_H
#define ATTR_LIST_H

#define ATTR_LIST_OK    1
#define ATTR_LIST_ERROR 0

#include <libssh/sftp.h>

/**
 * This file defined structs and functions that are used to create a linked list
 * of sftp_attributes.
 */

struct attributes_node {
    sftp_attributes         data;
    struct attributes_node* next;
};

typedef struct attributes_node* AttrNode;

struct attributes_list {
    AttrNode head;
    int      size;
};

typedef struct attributes_list* AttrList;

AttrList attr_list_initialize(void);

int attr_list_add(AttrList list, sftp_attributes attr);

AttrNode attr_list_get_from_postion(AttrList list, int index);

int attr_list_show(AttrList list);

int attr_list_show_with_index(AttrList list);

int attr_list_free(AttrList list);

#endif  // ATTR_LIST_H
