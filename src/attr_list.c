#include "attr_list.h"

#include <libssh/sftp.h>
#include <stdio.h>
#include <stdlib.h>

#include "pssh.h"

AttrList attr_list_initialize(void) {
    AttrList list = (AttrList)malloc(sizeof(struct attributes_list));
    if(list == NULL) {
        fprintf(stderr, "allocating memory to a list of attributes failed\n");
        return NULL;
    }

    list->head = NULL;
    list->size = 0;

    return list;
}

int attr_list_add(struct attributes_list* list, sftp_attributes attr) {
    if(list == NULL || attr == NULL) {
        fprintf(stdout, "list or attr should not be null\n");
        return ATTR_LIST_ERROR;
    }

    struct attributes_node* temp = list->head;

    for(int i = 0; i < list->size - 1; i++) {
        temp = temp->next;
        if(i != list->size - 1 && temp == NULL) {
            fprintf(stderr,
                    "Found NULL in the list before reaching the size\n");
            return ATTR_LIST_ERROR;
        }
    }

    if(temp != NULL && temp->next != NULL) {
        fprintf(
            stderr,
            "reached the end of the list accordding to size and the item is still not NULL\n");
        return ATTR_LIST_ERROR;
    }

    struct attributes_node* new =
        (struct attributes_node*)malloc(sizeof(struct attributes_node));
    if(new == NULL) {
        fprintf(stderr, "could not allocate memory for the node\n");
        return ATTR_LIST_ERROR;
    }
    new->data = attr;
    new->next = NULL;

    if(temp != NULL) {
        temp->next = new;
        list->size++;
    } else {
        list->head = new;
        list->size++;
    }

    return ATTR_LIST_OK;
}

/**
 * Finds the node at a partictular particulat position. The position starts from
 * 1
 */
AttrNode attr_list_get_from_postion(AttrList list, int index) {
    if(list == NULL) {
        fprintf(stderr, "list cannot be null\n");
        return NULL;
    }

    if(index > list->size || index <= 0) {
        fprintf(stdout,
                "cannot find %d index in a list with size %d\n",
                index,
                list->size);
        return NULL;
    }

    AttrNode temp = list->head;

    for(int i = 1; i < index; i++) {
        temp = temp->next;
    }

    return temp;
}

int attr_list_show(AttrList list) {
    if(list == NULL) {
        fprintf(stdout, "attributs list should not be null\n");
        return ATTR_LIST_ERROR;
    }

    AttrNode temp = list->head;

    for(int i = 0; i < list->size; i++) {
        printf("%s\n", temp->data->name);
        temp = temp->next;
    }

    return ATTR_LIST_OK;
}

int attr_list_show_with_index(AttrList list) {
    if(list == NULL) {
        fprintf(stdout, "attributs list should not be null\n");
        return ATTR_LIST_ERROR;
    }

    printf("0. (previous directory)\n");

    AttrNode temp = list->head;

    for(int i = 0; i < list->size; i++) {
        printf("%d. \e[%sm%s\e[0m\n",
               i + 1,
               get_file_type_color(temp->data->type),
               temp->data->name);
        temp = temp->next;
    }

    return ATTR_LIST_OK;
}

int attr_list_free(AttrList list) {
    if(list == NULL) {
        return ATTR_LIST_ERROR;
    }

    AttrNode temp = list->head;
    AttrNode perv = NULL;

    for(int i = 0; i < list->size; i++) {
        perv = temp;
        temp = temp->next;
        sftp_attributes_free(perv->data);
        free(perv);
    }

    free(list);
    return ATTR_LIST_OK;
}
