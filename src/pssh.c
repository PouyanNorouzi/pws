/**
 * function definitions for interactions with the pi server
 */

#include "pssh.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "attr_list.h"
#include "dynamic_str.h"
#include "path.h"

#ifndef _WIN32
#  include <bsd/readpassphrase.h>
#  include <unistd.h>
#else
#  include <_mingw_stat64.h>
#  include <conio.h>
#endif

/**
 * verify if the host is in the known host files and if not adds the host if
 * trusted.
 */
int verify_knownhost(ssh_session session) {
    enum ssh_known_hosts_e state;
    unsigned char*         hash       = NULL;
    ssh_key                srv_pubkey = NULL;
    size_t                 hlen;
    char                   buf[10];
    char*                  hexa;
    char*                  p;
    int                    cmp;
    int                    rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if(rc < 0) {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA256,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if(rc < 0) {
        return -1;
    }

    state = ssh_session_is_known_server(session);
    switch(state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */

            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
            fprintf(stderr,
                    "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);

            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr,
                    "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(
                stderr,
                "An attacker might change the default server key to"
                "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);

            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,
                    "The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if(p == NULL) {
                return -1;
            }

            cmp = strncasecmp(buf, "yes", 3);
            if(cmp != 0) {
                return -1;
            }

            rc = ssh_session_update_known_hosts(session);
            if(rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }

            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }

    ssh_clean_pubkey_hash(&hash);
    return 0;
}

/**
 * Authenticate user on the server based on a keyboard-interactive
 * authentication.
 */
int pauthenticate(ssh_session session) {
    int rc;

    rc = ssh_userauth_kbdint(session, NULL, NULL);
    while(rc == SSH_AUTH_INFO) {
        const char *name, *instruction;
        int         nprompts, iprompt;

        name        = ssh_userauth_kbdint_getname(session);
        instruction = ssh_userauth_kbdint_getinstruction(session);
        nprompts    = ssh_userauth_kbdint_getnprompts(session);

        if(strlen(name) > 0) {
            printf("%s\n", name);
        }
        if(strlen(instruction) > 0) {
            printf("%s\n", instruction);
        }
        for(iprompt = 0; iprompt < nprompts; iprompt++) {
            const char* prompt;
            char        echo;

            prompt = ssh_userauth_kbdint_getprompt(session, iprompt, &echo);
            if(echo) {
                char buffer[128], *ptr;

                printf("%s", prompt);
                if(fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    return SSH_AUTH_ERROR;
                }
                buffer[sizeof(buffer) - 1] = '\0';
                if((ptr = strchr(buffer, '\n')) != NULL) {
                    *ptr = '\0';
                }
                if(ssh_userauth_kbdint_setanswer(session, iprompt, buffer) <
                   0) {
                    return SSH_AUTH_ERROR;
                }
                memset(buffer, 0, strlen(buffer));
            } else {
                char buffer[BUFFER_SIZE];
                readpassphrase(prompt, buffer, BUFFER_SIZE, 0);
                if(ssh_userauth_kbdint_setanswer(session, iprompt, buffer) <
                   0) {
                    return SSH_AUTH_ERROR;
                }
            }
        }
        rc = ssh_userauth_kbdint(session, NULL, NULL);
    }
    return rc;
}

ssh_channel create_channel_with_open_session(ssh_session session) {
    ssh_channel channel = ssh_channel_new(session);
    if(channel == NULL) {
        fputs("Failed to open channel for the terminal", stderr);
        return NULL;
    }

    if(ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return NULL;
    }
    return channel;
}

sftp_session create_sftp_session(ssh_session session) {
    sftp_session sftp;
    int          rc;

    sftp = sftp_new(session);
    if(sftp == NULL) {
        fprintf(stderr,
                "Error allocating SFTP session: %s\n",
                ssh_get_error(session));
        return NULL;
    }

    rc = sftp_init(sftp);
    if(rc != SSH_OK) {
        fprintf(stderr,
                "Error initializing SFTP session: code %d.\n",
                sftp_get_error(sftp));
        sftp_free(sftp);
        return NULL;
    }

    return sftp;
}

/**
 * Returns the provided directories content. Simmilar to running ls.
 */
AttrList directory_ls_sftp(sftp_session session_sftp, Path path) {
    char* directory_name;

    if(session_sftp == NULL || path == NULL) {
        fprintf(stdout, "sftp session and directory name cannot be empty\n");
        return NULL;
    }

    directory_name = path->path->str;
    AttrList list  = attr_list_initialize();

    sftp_dir directory = sftp_opendir(session_sftp, directory_name);
    if(!directory) {
        fprintf(stderr,
                "Failed to open directory: %s\n",
                ssh_get_error(session_sftp));
        return NULL;
    }

    sftp_attributes attr;
    while((attr = sftp_readdir(session_sftp, directory)) != NULL) {
        // skip hidden files
        if(attr->name[0] == '.') {
            sftp_attributes_free(attr);
            continue;
        }
        attr_list_add(list, attr);
    }

    if(sftp_dir_eof(directory) != 1) {
        fprintf(stderr,
                "Failed to read directory: %s\n",
                ssh_get_error(session_sftp));
        sftp_closedir(directory);
        return NULL;
    }

    sftp_closedir(directory);
    return list;
}

int handle_file_sftp(sftp_session session, Path pwd, AttrNode node) {
    char  buffer[BUFFER_SIZE];
    Path  curr_dir;
    Path  default_path;
    char* pwdstr;

    if(pwd == NULL || node == NULL) {
        fprintf(stderr, "pwd or node cannot be empty\n");
        return SSH_ERROR;
    }

    pwdstr = pwd->path->str;

    if(node->data->type != SSH_FILEXFER_TYPE_REGULAR) {
        fprintf(stderr,
                "%s/%s is not a regular file\n",
                pwdstr,
                node->data->name);
        return SSH_ERROR;
    }

    curr_dir = path_init(pwdstr, PLATFORM_LINUX);
    path_go_into(curr_dir, node->data->name);

    default_path = path_get_downloads_directory();

    printf("%s is a regular file what do you want to do?\n",
           curr_dir->path->str);
    printf("1. Download the file\n");
    pfgets(buffer, BUFFER_SIZE);

    switch(buffer[0]) {
        case '1':
            download_file(session, curr_dir, default_path, node->data);
            break;
        default: printf("Invalid input going back\n"); break;
    }

    path_free(default_path);
    path_free(curr_dir);
    return SSH_OK;
}

int handle_directory_sftp(sftp_session session, Path pwd, AttrNode node) {
    Path  curr_dir;
    Path  default_path;
    char* pwdstr;
    char  buffer[BUFFER_SIZE];

    if(pwd == NULL || node == NULL) {
        fprintf(stderr, "pwd or node cannot be empty\n");
        return SSH_ERROR;
    }

    pwdstr = pwd->path->str;

    if(node->data->type != SSH_FILEXFER_TYPE_DIRECTORY) {
        fprintf(stderr, "%s/%s is not a directory\n", pwdstr, node->data->name);
        return SSH_ERROR;
    }

    curr_dir = path_init(pwdstr, PLATFORM_LINUX);
    path_go_into(curr_dir, node->data->name);

    default_path = path_get_downloads_directory();

    printf("%s is a directory what do you want to do?\n", pwdstr);
    printf("1. Download the directory recursively\n");
    printf("2. Go inside the directory\n");
    pfgets(buffer, BUFFER_SIZE);

    switch(buffer[0]) {
        case '1': download_directory(session, curr_dir, default_path); break;
        case '2': path_go_into(pwd, node->data->name); break;
        default:  printf("Invalid input going back\n"); break;
    }

    path_free(default_path);
    path_free(curr_dir);
    return SSH_OK;
}

int download_directory(sftp_session session, Path dir, Path location) {
    AttrList list;
    AttrNode node;
    Path     curr_download_location;
    Path     curr_downloading;
    char*    folder_name;

    if(session == NULL || dir == NULL) {
        fprintf(stderr, "session and dir path cannot be null\n");
        return SSH_ERROR;
    }

    curr_download_location = path_duplicate(location);
    folder_name            = path_get_curr(dir);

    path_go_into(curr_download_location, folder_name);

    free(folder_name);

    if(path_create_directory(curr_download_location) != 0) {
        fprintf(stderr,
                "Failed to create directory at %s\n",
                curr_download_location->path->str);
        path_free(curr_download_location);
        return SSH_ERROR;
    }

    list = directory_ls_sftp(session, dir);
    if(list == NULL) {
        path_free(curr_download_location);
        return SSH_OK;
    }

    curr_downloading = path_duplicate(dir);
    node             = list->head;
    while(node != NULL) {
        path_go_into(curr_downloading, node->data->name);

        if(node->data->type == SSH_FILEXFER_TYPE_REGULAR) {
            download_file(session,
                          curr_downloading,
                          curr_download_location,
                          node->data);
        } else if(node->data->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            download_directory(session,
                               curr_downloading,
                               curr_download_location);
        } else {
            printf("donwnload not supported for %s\n", node->data->name);
        }
        path_prev(curr_downloading);

        node = node->next;
    }

    attr_list_free(list);
    path_free(curr_download_location);
    path_free(curr_downloading);
    return SSH_OK;
}

int download_file(sftp_session    session,
                  Path            file,
                  Path            location,
                  sftp_attributes attr) {
    sftp_file          file_sftp;
    char               buffer[CHUNK_SIZE];
    Path               download_file;
    char*              file_name;
    char*              readable_size;
    char*              readable_written;
    FILE*              fp;
    ssize_t            nbytes;
    unsigned long long total_written = 0;

    file_sftp = sftp_open(session, file->path->str, O_RDONLY, 0);
    if(file_sftp == NULL) {
        fprintf(stderr, "could not open file\n");
        return SSH_ERROR;
    }

    file_name     = path_get_curr(file);
    download_file = path_duplicate(location);
    path_go_into(download_file, file_name);

    // TODO: CHECK IF THE FILE ALREADY EXISTS AND PROMPT FOR OVERRIDE
    fp = fopen(download_file->path->str, "wb");
    if(fp == NULL) {
        free(file_name);
        fprintf(stderr,
                "Failed to open file at %s\n",
                download_file->path->str);
        return SSH_ERROR;
    }
    // no longer needed
    path_free(download_file);

    readable_size = get_readable_size(attr->size);

    time_t last_report  = time(NULL);
    time_t current_time = last_report;
    while((nbytes = sftp_read(file_sftp, buffer, CHUNK_SIZE)) != 0) {
        if(nbytes < 0) {
            fprintf(stderr, "Error while reading from the file\n");
            fclose(fp);
            free(readable_size);
            free(file_name);
            sftp_close(file_sftp);
            return SSH_ERROR;
        }

        if(fwrite(buffer, sizeof(char), nbytes, fp) != (size_t)nbytes) {
            fprintf(stderr, "Error while writing to the file\n");
            fclose(fp);
            free(readable_size);
            free(file_name);
            sftp_close(file_sftp);
            return SSH_ERROR;
        }
        total_written += nbytes;

        current_time = time(NULL);
        if(current_time > last_report) {
            readable_written = get_readable_size(total_written);
            printf("\r[%s] wrote %s of %s",
                   file_name,
                   readable_written,
                   readable_size);
            fflush(stdout);
            last_report = time(NULL);
            free(readable_written);
        }
    }

    fclose(fp);
    free(readable_size);
    free(file_name);
    sftp_close(file_sftp);
    return SSH_OK;
}

int upload_directory(sftp_session session, Path from, Path to) {
    Path  to_directory;
    char* dir_name;
    int   rc;
    DIR*  local_dir;
    Path  curr_path;

    struct dirent* attr;
    struct stat    path_stat;

    if(session == NULL || from == NULL || to == NULL) {
        fprintf(stderr, "cannot pass null values to upload_file function\n");
        return SSH_ERROR;
    }

    dir_name = path_get_curr(from);
    if(dir_name == NULL) {
        fprintf(stderr, "Failed to get current file name from path\n");
        return SSH_ERROR;
    }

    to_directory = path_duplicate(to);
    if(to_directory == NULL) {
        fprintf(stderr, "Failed to duplicate path\n");
        free(dir_name);
        return SSH_ERROR;
    }

    rc = path_go_into(to_directory, dir_name);
    if(rc != PATH_OK) {
        fprintf(stderr, "Failed to go into path\n");
        free(dir_name);
        path_free(to_directory);
        return SSH_ERROR;
    }

    rc = sftp_mkdir(session, to_directory->path->str, S_IRWXU | S_IRWXG);
    if(rc != SSH_OK) {
        fprintf(stderr,
                "Failed to create remote directory: %d\n",
                sftp_get_error(session));
        path_free(to_directory);
        free(dir_name);
        return SSH_ERROR;
    }

    local_dir = path_opendir(from);
    if(local_dir == NULL) {
        fprintf(stderr,
                "Failed to open local directory: %s\n",
                from->path->str);
        path_free(to_directory);
        free(dir_name);
        return SSH_ERROR;
    }

    curr_path = path_duplicate(from);

    errno = 0;
    while((attr = readdir(local_dir)) != NULL) {
        if(attr->d_name[0] == '.') continue;

        stat(attr->d_name, &path_stat);

        path_go_into(curr_path, attr->d_name);
        // TODO: BETTER ERROR HANDLING
        if(S_ISDIR(path_stat.st_mode)) {
            upload_directory(session, curr_path, to_directory);
        } else if(S_ISREG(path_stat.st_mode)) {
            upload_file(session, curr_path, to_directory);
        } else {
            fprintf(stderr,
                    "cannot print the path %s skipping\n",
                    curr_path->path->str);
        }
        path_prev(curr_path);
    }

    if(errno != 0) {
        fprintf(stderr, "error reading the folder %d\n", errno);
        closedir(local_dir);
        path_free(to_directory);
        free(dir_name);
        return SSH_ERROR;
    }

    path_free(curr_path);
    closedir(local_dir);
    path_free(to_directory);
    free(dir_name);
    return SSH_OK;
}

int upload_file(sftp_session session, Path from, Path to_directory) {
    Path      to_file;
    char*     file_name;
    char*     readable_written;
    char*     readable_size;
    char      chunk[CHUNK_SIZE];
    int       rc;
    sftp_file remote_file;
    FILE*     local_file;
    size_t    nbytes;

    if(session == NULL || from == NULL || to_directory == NULL) {
        fprintf(stderr, "cannot pass null values to upload_file function\n");
        return SSH_ERROR;
    }

    file_name = path_get_curr(from);
    if(file_name == NULL) {
        fprintf(stderr, "Failed to get current file name from path\n");
        return SSH_ERROR;
    }

    to_file = path_duplicate(to_directory);
    if(to_file == NULL) {
        fprintf(stderr, "Failed to duplicate path\n");
        free(file_name);
        return SSH_ERROR;
    }

    rc = path_go_into(to_file, file_name);
    if(rc != PATH_OK) {
        fprintf(stderr, "Failed to go into path\n");
        free(file_name);
        path_free(to_file);
        return SSH_ERROR;
    }

    // TODO: MAKE IT SO THAT USER GETS THE OPTION TO OVERIDE IF EXISTS
    remote_file = sftp_open(session,
                            to_file->path->str,
                            O_WRONLY | O_CREAT | O_EXCL,
                            S_IRWXU | S_IRWXG);
    if(remote_file == NULL) {
        fprintf(stderr,
                "Failed to open remote file for writing: %s\n",
                ssh_get_error(session));
        path_free(to_file);
        free(file_name);
        return SSH_ERROR;
    }

    local_file = fopen(from->path->str, "rb");
    if(local_file == NULL) {
        fprintf(stderr,
                "Failed to open local file for reading: %s\n",
                from->path->str);
        sftp_close(remote_file);
        path_free(to_file);
        free(file_name);
        return SSH_ERROR;
    }

    unsigned long long total_written = 0;
    unsigned long long total_size    = path_get_file_size(from);

    readable_size = get_readable_size(total_size);

    time_t last_report  = time(NULL);
    time_t current_time = last_report;
    while((nbytes = fread(chunk, sizeof(char), CHUNK_SIZE, local_file)) != 0) {
        if(sftp_write(remote_file, chunk, nbytes) != (ssize_t)nbytes) {
            fprintf(stderr,
                    "Error writing to remote file: %d\n",
                    sftp_get_error(session));
            fclose(local_file);
            sftp_close(remote_file);
            path_free(to_file);
            free(file_name);
            return SSH_ERROR;
        }
        total_written += nbytes;

        current_time = time(NULL);
        if(current_time > last_report) {
            readable_written = get_readable_size(total_written);
            printf("\r[%s] wrote %s of %s",
                   file_name,
                   readable_written,
                   readable_size);
            fflush(stdout);
            last_report = time(NULL);
            free(readable_written);
        }
    }
    printf("\n");

    if(ferror(local_file)) {
        fprintf(stderr, "Error reading from local file: %s\n", from->path->str);
        fclose(local_file);
        sftp_close(remote_file);
        path_free(to_file);
        free(file_name);
        return SSH_ERROR;
    }

    fclose(local_file);
    sftp_close(remote_file);
    path_free(to_file);
    free(file_name);
    return SSH_OK;
}

int request_interactive_shell(ssh_channel channel) {
    int rc = ssh_channel_request_pty(channel);
    if(rc != SSH_OK) {
        return rc;
    }

    rc = ssh_channel_change_pty_size(channel, 80, 24);
    if(rc != SSH_OK) {
        return rc;
    }

    rc = ssh_channel_request_shell(channel);
    if(rc != SSH_OK) {
        return rc;
    }

    return rc;
}

/**
 * Executes a command and writes output to stdout.
 */
int execute_command_on_shell(ssh_channel channel, char* command) {
    char buffer[BUFFER_SIZE];
    int  nbytes;
    char command_with_nextline[strlen(command) + 1];

    // add nextline to the command so that it executes
    strncpy(command_with_nextline, command, strlen(command));
    strcat(command_with_nextline, "\n");

    ssh_channel_write(channel,
                      command_with_nextline,
                      strlen(command_with_nextline));
    // sleep(3);

    while(ssh_channel_read(channel, buffer, BUFFER_SIZE, 0) == 0);
    while((nbytes =
               ssh_channel_read_nonblocking(channel, buffer, BUFFER_SIZE, 0)) >
          0) {
        puts("read");
        if(fwrite(buffer, 1, nbytes, stdout) != (size_t)nbytes) {
            fprintf(stderr,
                    "Error writing \"%s\" command output to stdout: %s",
                    command,
                    ssh_get_error(channel));

            return SSH_ERROR;
        }
        puts("wrote");
        // usleep(5000L);
    }

    return 0;
}

int terminal_session(ssh_session session) {
    (void)session;
    puts("Not available yet");
    return 0;
}

int easy_navigate_mode_sftp(ssh_session session) {
    char     buffer[BUFFER_SIZE];
    Path     pwd;
    AttrList list;
    AttrNode node;
    int      quit = 0;

    sftp_session sftp = create_sftp_session(session);
    if(sftp == NULL) {
        return SSH_ERROR;
    }

    // set the present working direcrory as initial working directory
    pwd = path_init(INITIAL_WORKING_DIRECTORY, PLATFORM_LINUX);
    if(pwd == NULL) {
        sftp_free(sftp);
        return SSH_ERROR;
    }

    while(!quit) {
        printf("\nYou are now at \"%s\" directory\n", pwd->path->str);

        list = directory_ls_sftp(sftp, pwd);
        if(list == NULL) {
            path_free(pwd);
            sftp_free(sftp);
            return SSH_ERROR;
        }

        attr_list_show_with_index(list);
        printf("Choose a file or directory(0-%d) or q to quit\n", list->size);
        pfgets(buffer, BUFFER_SIZE);
        printf("\n");

        if(buffer[0] == 'q') {
            quit = 1;
        } else {
            // convert input to number and detect errors
            char* endptr;
            long  num = strtol(buffer, &endptr, 10);
            if(endptr == buffer) {
                printf("Invalid input, not a number\n");
                continue;
            }

            if(num < 0 || num > list->size) {
                fprintf(stderr,
                        "number %ld is not in range (%d-%d)\n",
                        num,
                        1,
                        list->size);
                continue;
            }

            if(num == 0) {
                path_prev(pwd);
                continue;
            }

            node = attr_list_get_from_postion(list, num);

            switch(node->data->type) {
                case SSH_FILEXFER_TYPE_REGULAR:
                    handle_file_sftp(sftp, pwd, node);
                    break;

                case SSH_FILEXFER_TYPE_DIRECTORY:
                    handle_directory_sftp(sftp, pwd, node);
                    break;

                case SSH_FILEXFER_TYPE_SYMLINK: puts("symlink"); break;

                case SSH_FILEXFER_TYPE_SPECIAL: puts("special"); break;

                default: puts("others"); break;
            }
        }
    }

    attr_list_free(list);
    path_free(pwd);
    sftp_free(sftp);
    return SSH_OK;
}

int upload_mode(ssh_session session) {
    char buffer[BUFFER_SIZE];
    Path uploaded;
    Path destination;

    if(session == NULL) {
        fprintf(stderr, "Error: SSH session is NULL.\n");
    }

    sftp_session sftp = create_sftp_session(session);
    if(sftp == NULL) {
        fprintf(stderr, "Error creating SFTP session.\n");
    }

    // TODO: BETTER ERROR HANDLING
    puts("enter the path of the file or directory you want to upload");
    pfgets(buffer, BUFFER_SIZE);
    uploaded = path_init(buffer, CURR_PLATFORM);

    puts("enter the path of the directory you want this to be uploaded to");
    pfgets(buffer, BUFFER_SIZE);
    destination = path_init(buffer, PLATFORM_LINUX);

    if(path_is_directory(uploaded)) {
        upload_directory(sftp, uploaded, destination);
    } else if(path_is_file(uploaded)) {
        upload_file(sftp, uploaded, destination);
    } else {
        fprintf(stderr, "Error finding the file to be uploaded\n");
        path_free(uploaded);
        path_free(destination);
        return SSH_ERROR;
    }

    path_free(uploaded);
    path_free(destination);
    return SSH_OK;
}

char* pfgets(char* string, int size) {
    size_t len;

    fgets(string, size, stdin);
    len = strlen(string);
    if(len > 0 && string[len - 1] == '\n') {
        string[len - 1] = '\0';
    }

    return string;
}

/**
 * Takes an integer and returns the corresponding static string of file type.
 */
char* get_file_type_str(int type) {
    switch(type) {
        case SSH_FILEXFER_TYPE_REGULAR: return FILE_TYPE_REGULAR_STR;

        case SSH_FILEXFER_TYPE_DIRECTORY: return FILE_TYPE_DIRECTORY_STR;

        case SSH_FILEXFER_TYPE_SYMLINK: return FILE_TYPE_SYMLINK_STR;

        case SSH_FILEXFER_TYPE_SPECIAL: return FILE_TYPE_SPECIAL_STR;

        default: return FILE_TYPE_UNKNOWN_STR;
    }
}

char* get_file_type_color(int type) {
    switch(type) {
        case SSH_FILEXFER_TYPE_REGULAR: return FILE_TYPE_REGULAR_COLOR;

        case SSH_FILEXFER_TYPE_DIRECTORY: return FILE_TYPE_DIRECTORY_COLOR;

        case SSH_FILEXFER_TYPE_SYMLINK: return FILE_TYPE_SYMLINK_COLOR;

        case SSH_FILEXFER_TYPE_SPECIAL: return FILE_TYPE_SPECIAL_COLOR;

        default: return FILE_TYPE_UNKNOWN_COLOR;
    }
}

char* get_readable_size(size_t size) {
    char* result;
    char  buffer[BUFFER_SIZE];

    if(size / BYTES_IN_KB == 0) {
        sprintf(buffer, "%luB", (unsigned long)size);
    } else if(size / BYTES_IN_MB == 0) {
        sprintf(buffer, "%.3fKB", (double)size / BYTES_IN_KB);
    } else if(size / BYTES_IN_GB == 0) {
        sprintf(buffer, "%.3fMB", (double)size / BYTES_IN_MB);
    } else {
        sprintf(buffer, "%.3fGB", (double)size / BYTES_IN_GB);
    }

    result = strdup(buffer);

    return result;
}

#ifdef _WIN32
/**
 * gets the password from the user and does not echo it on the terminal.
 */
char* readpassphrase(const char* prompt, char* buffer, int size, int flag) {
    if(prompt == NULL) {
        return NULL;
    }

    if(prompt != NULL) {
        printf("%s", prompt);
    }

    (void)flag;

    int i = 0;
    int ch;

    while(1) {
        ch = _getch();
        if(ch == '\r' || ch == '\n') {
            break;
        }
        if(ch == '\b') {
            if(i > 0) {
                i--;
            }
        } else if(i < size - 1) {
            buffer[i++] = (char)ch;
        }
    }

    buffer[i] = '\0';
    printf("\n");

    fflush(stdin);

    return buffer;
}
#endif
