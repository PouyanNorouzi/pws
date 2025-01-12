/**
 * function definitions for interactions with the pi server
 */

#include "pssh.h"
#include "attr_list.h"
#include "dynamic_str.h"
#include <stdio.h>
#include <stdlib.h>
#include <libssh/libssh.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#ifndef _WIN32
#include <bsd/readpassphrase.h>
#else
#include <conio.h>
#endif

const char* download_location = "/home/batmanpouknight/Downloads";

/**
 * verify if the host is in the known host files and if not adds the host if trusted.
 */
int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char* hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char* hexa;
    char* p;
    int cmp;
    int rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if(rc < 0)
    {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if(rc < 0)
    {
        return -1;
    }

    state = ssh_session_is_known_server(session);
    switch(state)
    {
    case SSH_KNOWN_HOSTS_OK:
        /* OK */

        break;
    case SSH_KNOWN_HOSTS_CHANGED:
        fprintf(stderr, "Host key for server changed: it is now:\n");
        ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
        fprintf(stderr, "For security reasons, connection will be stopped\n");
        ssh_clean_pubkey_hash(&hash);

        return -1;
    case SSH_KNOWN_HOSTS_OTHER:
        fprintf(stderr, "The host key for this server was not found but an other"
                "type of key exists.\n");
        fprintf(stderr, "An attacker might change the default server key to"
                "confuse your client into thinking the key does not exist\n");
        ssh_clean_pubkey_hash(&hash);

        return -1;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
    case SSH_KNOWN_HOSTS_UNKNOWN:
        hexa = ssh_get_hexa(hash, hlen);
        fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
        fprintf(stderr, "Public key hash: %s\n", hexa);
        ssh_string_free_char(hexa);
        ssh_clean_pubkey_hash(&hash);
        p = fgets(buf, sizeof(buf), stdin);
        if(p == NULL)
        {
            return -1;
        }

        cmp = strncasecmp(buf, "yes", 3);
        if(cmp != 0)
        {
            return -1;
        }

        rc = ssh_session_update_known_hosts(session);
        if(rc < 0)
        {
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
 * Authenticate user on the server based on a keyboard-interactive authentication.
 */
int pauthenticate(ssh_session session)
{
    int rc;

    rc = ssh_userauth_kbdint(session, NULL, NULL);
    while(rc == SSH_AUTH_INFO)
    {
        const char* name, * instruction;
        int nprompts, iprompt;

        name = ssh_userauth_kbdint_getname(session);
        instruction = ssh_userauth_kbdint_getinstruction(session);
        nprompts = ssh_userauth_kbdint_getnprompts(session);

        if(strlen(name) > 0)
            printf("%s\n", name);
        if(strlen(instruction) > 0)
            printf("%s\n", instruction);
        for(iprompt = 0; iprompt < nprompts; iprompt++)
        {
            const char* prompt;
            char echo;

            prompt = ssh_userauth_kbdint_getprompt(session, iprompt, &echo);
            if(echo)
            {
                char buffer[128], * ptr;

                printf("%s", prompt);
                if(fgets(buffer, sizeof(buffer), stdin) == NULL)
                    return SSH_AUTH_ERROR;
                buffer[sizeof(buffer) - 1] = '\0';
                if((ptr = strchr(buffer, '\n')) != NULL)
                    *ptr = '\0';
                if(ssh_userauth_kbdint_setanswer(session, iprompt, buffer) < 0)
                    return SSH_AUTH_ERROR;
                memset(buffer, 0, strlen(buffer));
            } else
            {
                char buffer[BUFFER_SIZE];
                readpassphrase(prompt, buffer, BUFFER_SIZE, 0);
                if(ssh_userauth_kbdint_setanswer(session, iprompt, buffer) < 0)
                    return SSH_AUTH_ERROR;
            }
        }
        rc = ssh_userauth_kbdint(session, NULL, NULL);
    }
    return rc;
}

ssh_channel create_channel_with_open_session(ssh_session session)
{
    ssh_channel channel = ssh_channel_new(session);
    if(channel == NULL)
    {
        fputs("Failed to open channel for the terminal", stderr);
        return NULL;
    }

    if(ssh_channel_open_session(channel) != SSH_OK)
    {
        ssh_channel_free(channel);
        return NULL;
    }
    return channel;
}

sftp_session create_sftp_session(ssh_session session)
{
    sftp_session sftp;
    int rc;

    sftp = sftp_new(session);
    if(sftp == NULL)
    {
        fprintf(stderr, "Error allocating SFTP session: %s\n",
                ssh_get_error(session));
        return NULL;
    }

    rc = sftp_init(sftp);
    if(rc != SSH_OK)
    {
        fprintf(stderr, "Error initializing SFTP session: code %d.\n",
                sftp_get_error(sftp));
        sftp_free(sftp);
        return NULL;
    }

    return sftp;
}

/**
 * Returns the provided directories content. Simmilar to running ls.
 */
AttrList directory_ls_sftp(sftp_session session_sftp, const char* directory_name)
{
    if(session_sftp == NULL || directory_name == NULL)
    {
        fprintf(stdout, "sftp session and directory name cannot be empty\n");
        return NULL;
    }

    AttrList list = attr_list_initialize();

    sftp_dir directory = sftp_opendir(session_sftp, directory_name);
    if(!directory)
    {
        fprintf(stderr, "Failed to open directory: %s\n", ssh_get_error(session_sftp));
        return NULL;
    }

    sftp_attributes attr;
    while((attr = sftp_readdir(session_sftp, directory)) != NULL)
    {
        // skip hidden files
        if(attr->name[0] == '.')
        {
            sftp_attributes_free(attr);
            continue;
        }
        attr_list_add(list, attr);
    }

    if(sftp_dir_eof(directory) != 1)
    {
        fprintf(stderr, "Failed to read directory: %s\n", ssh_get_error(session_sftp));
        sftp_closedir(directory);
        return NULL;
    }

    sftp_closedir(directory);
    return list;
}

/**
 * Takes the pwd string and removes the name of the current directory in order to move to the directory
 * on top of it.
 */
int go_to_top_directory(DynamicStr pwd)
{
    int i = pwd->size;

    if(pwd == NULL || i == 1)
    {
        fprintf(stderr, "pwd cannot be null or empty\n");
        return SSH_ERROR;
    }

    if(strcmp(pwd->str, "/") == 0)
    {
        fprintf(stderr, "cannot move to before the root directory");
        return SSH_ERROR;
    }

    i--;
    while(i > 0 && pwd->str[i] != '/')
        i--;

    i = (i == 0) ? 1 : i;

    dynamic_str_remove(pwd, i);

    return SSH_OK;
}

/**
 * change pwd to go inside node if it is a direcotry.
 */
int cd_sftp(DynamicStr pwd, AttrNode node)
{
    int rc;

    if(pwd == NULL || node == NULL)
    {
        fprintf(stderr, "pwd or node or cannot be null\n");
        return SSH_ERROR;
    }

    // if the array is just '/' and '\0' we are at root directory
    if(pwd->size != 2)
    {
        rc = dynamic_str_cat(pwd, "/");
        if(rc != DYNAMIC_STR_OK)
        {
            fprintf(stderr, "error concaconating pwd\n");
            return SSH_ERROR;
        }
    }

    rc = dynamic_str_cat(pwd, node->data->name);
    if(rc != DYNAMIC_STR_OK)
    {
        fprintf(stderr, "error concaconating pwd\n");
        return SSH_ERROR;
    }

    return SSH_OK;
}

int handle_file_sftp(sftp_session session, DynamicStr pwd, AttrNode node)
{
    if(pwd == NULL || node == NULL)
    {
        fprintf(stderr, "pwd or node cannot be empty\n");
        return SSH_ERROR;
    }

    if(node->data->type != SSH_FILEXFER_TYPE_REGULAR)
    {
        fprintf(stderr, "%s/%s is not a regular file\n", pwd->str, node->data->name);
        return SSH_ERROR;
    }

    char buffer[BUFFER_SIZE];
    DynamicStr curr_dir = dynamic_str_init(pwd->str);

    cd_sftp(curr_dir, node);

    printf("%s is a regular file what do you want to do?\n", pwd->str);
    printf("1. Download the file\n");
    pfgets(buffer, BUFFER_SIZE);

    switch(buffer[0])
    {
    case '1':
        download_file(session, curr_dir->str, download_location, node);
        break;
    default:
        printf("Invalid input going back\n");
        break;
    }

    dynamic_str_free(curr_dir);
    return SSH_OK;
}

int handle_directory_sftp(sftp_session session, DynamicStr pwd, AttrNode node)
{
    if(pwd == NULL || node == NULL)
    {
        fprintf(stderr, "pwd or node cannot be empty\n");
        return SSH_ERROR;
    }

    if(node->data->type != SSH_FILEXFER_TYPE_DIRECTORY)
    {
        fprintf(stderr, "%s/%s is not a directory\n", pwd->str, node->data->name);
        return SSH_ERROR;
    }

    char buffer[BUFFER_SIZE];
    DynamicStr curr_dir = dynamic_str_init(pwd->str);

    cd_sftp(curr_dir, node);

    printf("%s is a directory what do you want to do?\n", pwd->str);
    printf("1. Download the directory recursively\n");
    printf("2. Go inside the directory\n");
    pfgets(buffer, BUFFER_SIZE);

    switch(buffer[0])
    {
    case '1':
        download_directory(session, curr_dir->str);
        break;
    case '2':
        cd_sftp(pwd, node);
        break;
    default:
        printf("Invalid input going back\n");
        break;
    }

    dynamic_str_free(curr_dir);
    return SSH_OK;
}

int download_directory(sftp_session session, char* dir)
{
    DynamicStr curr_download_location;
    char* folder_name;

    if(session == NULL || dir == NULL)
    {
        fprintf(stderr, "session and dir path cannot be null\n");
        return SSH_ERROR;
    }

    sftp_dir directory = sftp_opendir(session, dir);
    if(!directory)
    {
        fprintf(stderr, "Failed to open directory: %s\n", ssh_get_error(session));
        return SSH_ERROR;
    }

    curr_download_location = dynamic_str_init(download_location);
    folder_name = get_filename_from_path(dir);

    dynamic_str_cat(curr_download_location, "/");
    dynamic_str_cat(curr_download_location, folder_name);

    free(folder_name);

    sftp_attributes attr;
    while((attr = sftp_readdir(session, directory)) != NULL)
    {
        //download
    }

    if(sftp_dir_eof(directory) != 1)
    {
        fprintf(stderr, "Failed to read directory: %s\n", ssh_get_error(session));
        dynamic_str_free(curr_download_location);
        sftp_closedir(directory);
        return SSH_ERROR;
    }

    dynamic_str_free(curr_download_location);
    sftp_closedir(directory);
    return SSH_OK;
}

int download_file(sftp_session session, char* file, const char* location, AttrNode node)
{
    sftp_file file_sftp;
    char buffer[DOWNLOAD_CHUNK_SIZE];
    char* download_file;
    char* file_name;
    FILE* fp;
    ssize_t nbytes;
    unsigned long long total_written = 0;

    file_sftp = sftp_open(session, file, O_RDONLY, 0);
    if(file_sftp == NULL)
    {
        fprintf(stderr, "could not open file\n");
        return SSH_ERROR;
    }

    // TODO write better code
    file_name = get_filename_from_path(file);
    download_file = (char*)malloc(sizeof(char) * (strlen(location) + strlen(file_name) + 2));
    strcpy(download_file, location);
    strcat(download_file, "/");
    strcat(download_file, file_name);
    printf("%s\n", download_file);

    fp = fopen(download_file, "w");
    if(fp == NULL)
    {
        fprintf(stderr, "Failed to open file at %s\n", download_file);
        return SSH_ERROR;
    }
    // no longer needed
    free(download_file);
    free(file_name);

    while((nbytes = sftp_read(file_sftp, buffer, DOWNLOAD_CHUNK_SIZE)) != 0)
    {
        if(nbytes < 0)
        {
            fprintf(stderr, "Error while reading from the file\n");
            sftp_close(file_sftp);
            return SSH_OK;
        }

        if(((ssize_t)fwrite(buffer, sizeof(char), DOWNLOAD_CHUNK_SIZE, fp)) != nbytes)
        {
            fprintf(stderr, "Error while writing to the file\n");
            sftp_close(file_sftp);
            return SSH_OK;
        }
        total_written += nbytes;
        printf("wrote %llu of %lu \n", total_written, node->data->size);
    }

    sftp_close(file_sftp);
    return SSH_OK;
}

int request_interactive_shell(ssh_channel channel)
{
    int rc = ssh_channel_request_pty(channel);
    if(rc != SSH_OK) return rc;

    rc = ssh_channel_change_pty_size(channel, 80, 24);
    if(rc != SSH_OK) return rc;

    rc = ssh_channel_request_shell(channel);
    if(rc != SSH_OK) return rc;

    return rc;
}

/**
 * Executes a command and writes output to stdout.
 */
int execute_command_on_shell(ssh_channel channel, char* command)
{
    char buffer[BUFFER_SIZE];
    int nbytes;
    char command_with_nextline[strlen(command) + 1];

    // add nextline to the command so that it executes
    strncpy(command_with_nextline, command, strlen(command));
    strcat(command_with_nextline, "\n");

    ssh_channel_write(channel, command_with_nextline, strlen(command_with_nextline));
    // sleep(3);

    while(ssh_channel_read(channel, buffer, BUFFER_SIZE, 0) == 0);
    while((nbytes = ssh_channel_read_nonblocking(channel, buffer, BUFFER_SIZE, 0)) > 0)
    {
        puts("read");
        if(fwrite(buffer, 1, nbytes, stdout) != (size_t)nbytes)
        {
            fprintf(stderr, "Error writing \"%s\" command output to stdout: %s",
                    command, ssh_get_error(channel));

            return SSH_ERROR;
        }
        puts("wrote");
        // usleep(5000L);
    }

    return 0;
}

/**
 * Print the home menu that allows the user to open a new terminal session
 */
void print_home_menu(void)
{
    puts("You are at home menu type in the number of the action you want to do (0 or quit to quit)");
    puts("1. open new terminal session(does not work)");
    puts("2. easy navigate mode(neither does this)");
    puts("3. easy navigate mode sftp");
}

int terminal_session(ssh_session session)
{
    (void)session;
    puts("Not available yet");
    return 0;
}

int easy_navigate_mode(ssh_session session)
{
    ssh_channel channel = create_channel_with_open_session(session);
    if(channel == NULL)
    {
        fprintf(stderr, "Failed to open channel for the terminal %s\n", ssh_get_error(session));
        return SSH_ERROR;
    }

    if(request_interactive_shell(channel) != SSH_OK)
    {
        fprintf(stderr, "Failed to request shell %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    //TODO: find a better way to do this in case the wait should be longer
    //wait 1 second for the shell to start.
    sleep(1);

    // Empty the input
    size_t nbytes;
    char buffer[BUFFER_SIZE];
    while((nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0)) > 0)
    {
        puts("Emptied");
    }

    if(execute_command_on_shell(channel, "ps aux") != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_OK;
}

int easy_navigate_mode_sftp(ssh_session session)
{
    char buffer[BUFFER_SIZE];
    DynamicStr pwd;
    AttrList list;
    AttrNode node;
    int quit = 0;

    sftp_session sftp = create_sftp_session(session);
    if(sftp == NULL)
    {
        return SSH_ERROR;
    }

    // set the present working direcrory as initial working directory
    pwd = dynamic_str_init(INITIAL_WORKING_DIRECTORY);
    if(pwd == NULL)
    {
        sftp_free(sftp);
        return SSH_ERROR;
    }

    while(!quit)
    {
        printf("\nYou are now at \"%s\" directory\n", pwd->str);

        list = directory_ls_sftp(sftp, pwd->str);
        if(list == NULL)
        {
            dynamic_str_free(pwd);
            sftp_free(sftp);
            return SSH_ERROR;
        }

        attr_list_show_with_index(list);
        printf("Choose a file or directory(0-%d) or q to quit\n", list->size);
        pfgets(buffer, BUFFER_SIZE);
        printf("\n");

        if(buffer[0] == 'q')
        {
            quit = 1;
        } else
        {
            // convert input to number and detect errors
            char* endptr;
            long num = strtol(buffer, &endptr, 10);
            if(endptr == buffer)
            {
                printf("Invalid input, not a number\n");
                continue;
            }

            if(num < 0 || num > list->size)
            {
                fprintf(stderr, "number %ld is not in range (%d-%d)\n", num, 1, list->size);
                continue;
            }

            if(num == 0)
            {
                go_to_top_directory(pwd);
                continue;
            }

            node = attr_list_get_from_postion(list, num);

            switch(node->data->type)
            {
            case SSH_FILEXFER_TYPE_REGULAR:
                handle_file_sftp(sftp, pwd, node);
                break;

            case SSH_FILEXFER_TYPE_DIRECTORY:
                handle_directory_sftp(sftp, pwd, node);
                break;

            case SSH_FILEXFER_TYPE_SYMLINK:
                puts("symlink");
                break;

            case SSH_FILEXFER_TYPE_SPECIAL:
                puts("special");
                break;

            default:
                puts("others");
                break;
            }
        }
    }

    attr_list_free(list);
    dynamic_str_free(pwd);
    sftp_free(sftp);
    return SSH_OK;
}

char* pfgets(char* string, int size)
{
    size_t len;

    fgets(string, size, stdin);
    len = strlen(string);
    if(len > 0 && string[len - 1] == '\n')
    {
        string[len - 1] = '\0';
    }

    return string;
}

/**
 * Takes an integer and returns the corresponding static string of file type.
 */
char* get_file_type_str(int type)
{
    switch(type)
    {
    case SSH_FILEXFER_TYPE_REGULAR:
        return FILE_TYPE_REGULAR_STR;

    case SSH_FILEXFER_TYPE_DIRECTORY:
        return FILE_TYPE_DIRECTORY_STR;

    case SSH_FILEXFER_TYPE_SYMLINK:
        return FILE_TYPE_SYMLINK_STR;

    case SSH_FILEXFER_TYPE_SPECIAL:
        return FILE_TYPE_SPECIAL_STR;

    default:
        return FILE_TYPE_UNKNOWN_STR;
    }
}

char* get_file_type_color(int type)
{
    switch(type)
    {
    case SSH_FILEXFER_TYPE_REGULAR:
        return FILE_TYPE_REGULAR_COLOR;

    case SSH_FILEXFER_TYPE_DIRECTORY:
        return FILE_TYPE_DIRECTORY_COLOR;

    case SSH_FILEXFER_TYPE_SYMLINK:
        return FILE_TYPE_SYMLINK_COLOR;

    case SSH_FILEXFER_TYPE_SPECIAL:
        return FILE_TYPE_SPECIAL_COLOR;

    default:
        return FILE_TYPE_UNKNOWN_COLOR;
    }
}

/**
 * returns the name of the file based on the path name.
 * must be used with free to deallocate the returned pointer.
 */
static char* get_filename_from_path(char* path)
{
    char* filename;
    int i = strlen(path) - 1;

    while(i > 0 && path[i] != '/')
        i--;

    filename = (char*)malloc(sizeof(char) * (strlen(path) - i));

    strcpy(filename, path + i + 1);

    return filename;
}
#ifdef _WIN32
/**
 * gets the password from the user and does not echo it on the terminal.
 */
char* readpassphrase(const char* prompt, char* buffer, int size, int flag)
{
    if(prompt == NULL)
    {
        return NULL;
    }

    if(prompt != NULL)
    {
        printf("%s", prompt);
    }

    (void)flag;

    int i = 0;
    int ch;

    while(1)
    {
        ch = _getch();
        if(ch == '\r' || ch == '\n')
        {
            break;
        }
        if(ch == '\b')
        {
            if(i > 0)
            {
                i--;
            }
        } else if(i < size - 1)
        {
            buffer[i++] = (char)ch;
        }
    }

    buffer[i] = '\0';
    printf("\n");

    return buffer;
}
#endif