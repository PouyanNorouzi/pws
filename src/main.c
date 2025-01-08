#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include "pssh.h"

/**
 * The command line interface for the application
 */
int main(void)
{
    int verbosity = SSH_LOG_NONE;
    char* user = "remoteuser";
    char* host;
    char buffer[BUFFER_SIZE];

    printf("Enter name of host: ");
    pfgets(buffer, BUFFER_SIZE);
    host = (char*)malloc(sizeof(char) * strlen(buffer));
    strcpy(host, buffer);

    ssh_session session = ssh_new();
    if(session == NULL)
    {
        fprintf(stderr, "failed to create ssh session\n");
        exit(-1);
    }

    // get the host name from environment variable 
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_USER, user);
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    // Connect to the server
    if(ssh_connect(session) != SSH_OK)
    {
        fprintf(stderr, "Error connecting to %s: %s\n", host, ssh_get_error(session));
        exit(-1);
    }

    if(verify_knownhost(session) < 0)
    {
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    }

    if(pauthenticate(session) != 0)
    {
        puts("Wrong password");
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    }

    printf("You are now connected to \"%s\" user at host \"%s\"\n", user, host);

    do
    {
        print_home_menu();
        pfgets(buffer, BUFFER_SIZE);

        if(strcmp(buffer, "1") == 0)
        {
            terminal_session(session);
        } else if(strcmp(buffer, "2") == 0)
        {
            easy_navigate_mode(session);
        } else if(strcmp(buffer, "3") == 0)
        {
            easy_navigate_mode_sftp(session);
        }
    } while(strcmp(buffer, "quit") != 0 && strcmp(buffer, "0") != 0);

    free(host);
    ssh_disconnect(session);
    ssh_free(session);
    return 0;
}
