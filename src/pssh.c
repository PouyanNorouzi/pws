/**
 * function definitions for interactions with the pi server
 */

#include "pssh.h"
#include <stdio.h>
#include <stdlib.h>
#include <libssh/libssh.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

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
        ssh_print_hexa("Public key hash", hash, hlen);
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
        fprintf(stderr, "Could not find known host file.\n");
        fprintf(stderr, "If you accept the host key here, the file will be"
                "automatically created.\n");

        /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */

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
                char* ptr;

                ptr = getpass(prompt);
                if(ssh_userauth_kbdint_setanswer(session, iprompt, ptr) < 0)
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

int request_interactive_shell(ssh_channel channel)
{
    int rc = ssh_channel_request_pty(channel);
    if(rc != SSH_OK) return rc;

    // rc = ssh_channel_change_pty_size(channel, 80, 24);
    // if(rc != SSH_OK) return rc;

    rc = ssh_channel_request_shell(channel);
    if(rc != SSH_OK) return rc;
}

/**
 * Print the home menu that allows the user to open a new terminal session
 */
void print_home_menu(void)
{
    puts("You are at home menu type in the number of the action you want to do (0 or quit to quit)");
    puts("1. open new terminal session");
}

int terminal_session(ssh_session session)
{
    ssh_channel channel = create_channel_with_open_session(session);
    if(channel == NULL)
    {
        fprintf(stderr, "Failed to open channel for the terminal %s\n", ssh_get_error(session));
        return -1;
    }

    if(request_interactive_shell(channel) != SSH_OK)
    {
        fprintf(stderr, "Failed to request shell %s\n", ssh_get_error(session));
        return -1;
    }

    char buffer[256];
    int nbytes, nwritten;
    while(ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel))
    {
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
        if(nbytes < 0) return SSH_ERROR;
        if(nbytes > 0)
        {
            nwritten = write(1, buffer, nbytes);
            if(nwritten != nbytes) return SSH_ERROR;

            if(!kbhit())
            {
                usleep(50000L); // 0.05 second
                continue;
            }

            nbytes = read(0, buffer, sizeof(buffer));
            if(nbytes < 0) return SSH_ERROR;
            if(nbytes > 0)
            {
                nwritten = ssh_channel_write(channel, buffer, nbytes);
                if(nwritten != nbytes) return SSH_ERROR;
            }
        }
    }
    printf("out the loop: %d %d\n", ssh_channel_is_open(channel), !ssh_channel_is_eof(channel));

    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return 0;
}

char* pfgets(char* string, int size, FILE* fp)
{
    fgets(string, size, fp);
    string[strlen(string) - 1] = '\0';

    return string;
}

int kbhit(void)
{
    struct timeval tv = { 0L, 0L };
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(0, &fds);

    return select(1, &fds, NULL, NULL, &tv);
}