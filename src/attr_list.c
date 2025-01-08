#include "attr_list.h"
#include <libssh/sftp.h>
#include <stdio.h>

AttrList attr_list_initialize(void)
{
    AttrList list = (AttrList)malloc(sizeof(AttrList));
    if(list == NULL)
    {
        fprintf(stderr, "allocating memory to a list of attributes failed\n");
        return NULL;
    }

    list->head = NULL;
    list->size = 0;

    return list;
}

int attr_list_add(AttrList list, sftp_attributes attr)
{
    if(list == NULL || attr == NULL)
    {
        fprintf(stdout, "list or attr should not be null\n");
        return 1;
    }

    AttrNode temp = list->head;

    for(int i = 0; i < list->size; i++)
    {
        temp = temp->next;
        if(i != list->size - 1 && temp == NULL)
        {
            fprintf(stderr, "Found NULL in the list before reaching the size\n");
            return 1;
        }
    }

    if(temp != NULL)
    {
        fprintf(stderr, "reached the end of the list accordding to size and the item is still not NULL\n");
        return 1;
    }

    temp = (AttrNode)malloc(sizeof(AttrNode));

    temp->data = attr;
    temp->next = NULL;

    return 0;
}

int attr_list_free(AttrList list)
{
    if(list == NULL)
    {
        return 1;
    }

    AttrNode temp = list->head;
    AttrNode perv = NULL;

    for(int i = 0; i < list->size; i++)
    {
        perv = temp;
        temp = temp->next;
        sftp_attributes_free(temp->data);
        free(temp);
    }

    free(list);
    return 0;
}