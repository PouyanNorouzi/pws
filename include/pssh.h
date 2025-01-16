/**
 * Function definitions and symbolic constants for the interactions with the pi servers.
 */

#ifndef PSSH_H
#define PSSH_H
#include "attr_list.h"
#include "dynamic_str.h"
#include "path.h"
#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#define BUFFER_SIZE 256

#define DOWNLOAD_CHUNK_SIZE 32768

#define BYTES_IN_KB 1024
#define BYTES_IN_MB (1024 * 1024)
#define BYTES_IN_GB (1024 * 1024 * 1024)

#define MAX_DIRECTORY_LENGTH 256
#define INITIAL_WORKING_DIRECTORY "/media/ssd"


#define FILE_TYPE_REGULAR_STR "regular"
#define FILE_TYPE_DIRECTORY_STR "directory"
#define FILE_TYPE_SYMLINK_STR "symbolic link"
#define FILE_TYPE_SPECIAL_STR "special"
#define FILE_TYPE_UNKNOWN_STR "unknown"

#define FILE_TYPE_REGULAR_COLOR "0;37" // white
#define FILE_TYPE_DIRECTORY_COLOR "0;34" // blue
#define FILE_TYPE_SYMLINK_COLOR "0;36" // cyan
#define FILE_TYPE_SPECIAL_COLOR "0;32" // green
#define FILE_TYPE_UNKNOWN_COLOR "0;31" // red


int verify_knownhost(ssh_session session);

int pauthenticate(ssh_session session);

ssh_channel create_channel_with_open_session(ssh_session session);

sftp_session create_sftp_session(ssh_session session);

AttrList directory_ls_sftp(sftp_session session_sftp, Path path);

int handle_file_sftp(sftp_session session, Path pwd, AttrNode node);

int handle_directory_sftp(sftp_session session, Path pwd, AttrNode node);

int download_directory(sftp_session session, Path dir, Path location);

int download_file(sftp_session session, Path file, Path location, sftp_attributes attr);

int request_interactive_shell(ssh_channel channel);

int execute_command_on_shell(ssh_channel channel, char* command);

void print_home_menu(void);

int terminal_session(ssh_session session);

int easy_navigate_mode(ssh_session session);

int easy_navigate_mode_sftp(ssh_session session);

char* pfgets(char* string, int size);

char* get_file_type_str(int type);

char* get_file_type_color(int type);

char* get_readable_size(size_t size);

#ifdef _WIN32
char* readpassphrase(const char* prompt, char* buffer, int size, int flag);
#endif

#endif // PSSH_H