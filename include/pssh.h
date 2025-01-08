/**
 * Function definitions and symbolic constants for the interactions with the pi servers.
 */

#ifndef PSSH_H
#define PSSH_H
#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#define BUFFER_SIZE 256

#define MAX_DIRECTORY_LENGTH 256
#define INITIAL_WORKING_DIRECTORY "/media/hdd"

#define FILE_TYPE_REGULAR_STR "regular"
#define FILE_TYPE_DIRECTORY_STR "directory"
#define FILE_TYPE_SYMLINK_STR "symbolic link"
#define FILE_TYPE_SPECIAL_STR "special"
#define FILE_TYPE_UNKNOWN_STR "unknown"


int verify_knownhost(ssh_session session);

int pauthenticate(ssh_session session);

ssh_channel create_channel_with_open_session(ssh_session session);

sftp_session create_sftp_session(ssh_session session);

int directory_ls_sftp(sftp_session session_sftp, const char* directory_name);

int request_interactive_shell(ssh_channel channel);

int execute_command_on_shell(ssh_channel channel, char* command);

void print_home_menu(void);

int terminal_session(ssh_session session);

int easy_navigate_mode(ssh_session session);

int easy_navigate_mode_sftp(ssh_session session);

char* pfgets(char* string, int size);

char* get_file_type(int type);

#ifdef _WIN32
char* readpassphrase(const char* prompt, char* buffer, int size, int flag);
#endif

#endif // PSSH_H