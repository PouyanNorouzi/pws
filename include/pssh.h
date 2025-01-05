/**
 * Function definitions and symbolic constants for the interactions with the pi servers.
 */

#ifndef PSSH_H
#define PSSH_H
#include <stdio.h>
#include <libssh/libssh.h>
#define BUFFER_SIZE 256

int verify_knownhost(ssh_session session);

int pauthenticate(ssh_session session);

ssh_channel create_channel_with_open_session(ssh_session session);

int request_interactive_shell(ssh_channel channel);

int execute_command(ssh_session session, char* command);

void print_home_menu(void);

int terminal_session(ssh_session session);

int easy_navigate_mode(ssh_session session);

char* pfgets(char* string, int size, FILE* fp);

int kbhit(void);

#endif // PSSH_H