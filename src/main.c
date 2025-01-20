#include "main.h"

#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pssh.h"

/**
 * The command line interface for the application
 */
int main(void) {
    int   verbosity = SSH_LOG_NOLOG;
    int   port      = 22;
    char* user      = "remoteuser";
    char* host;
    char  buffer[BUFFER_SIZE];

    printf("Enter name of host: ");
    pfgets(buffer, BUFFER_SIZE);
    host = strdup(buffer);

    ssh_session session = ssh_new();
    if(session == NULL) {
        fprintf(stderr, "failed to create ssh session\n");
        free(host);
        exit(-1);
    }

    // get the host name from environment variable
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_USER, user);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    // Connect to the server
    if(ssh_connect(session) != SSH_OK) {
        fprintf(stderr,
                "Error connecting to %s: %s\n",
                host,
                ssh_get_error(session));
        free(host);
        exit(-1);
    }

    if(verify_knownhost(session) < 0) {
        ssh_disconnect(session);
        ssh_free(session);
        free(host);
        exit(-1);
    }

    if(pauthenticate(session) != 0) {
        puts("Wrong password");
        ssh_disconnect(session);
        ssh_free(session);
        free(host);
        exit(-1);
    }

    printf("You are now connected to \"%s\" user at host \"%s\"\n", user, host);

    do {
        print_home_menu();
        pfgets(buffer, BUFFER_SIZE);

        if(strcmp(buffer, "1") == 0) {
            terminal_session(session);
        } else if(strcmp(buffer, "2") == 0) {
            upload_mode(session);
        } else if(strcmp(buffer, "3") == 0) {
            easy_navigate_mode_sftp(session);
        }

    } while(buffer[0] != 'q' && buffer[0] != '0');

    ssh_disconnect(session);
    ssh_free(session);
    free(host);
    return 0;
}

/**
 * Print the home menu that allows the user to open a new terminal session
 */
void print_home_menu(void) {
    puts(
        "You are at home menu type in the number of the action you want to do "
        "(0 or quit to quit)");
    puts("1. open new terminal session(does not work)");
    puts("2. upload mode");
    puts("3. easy navigate mode sftp");
}
