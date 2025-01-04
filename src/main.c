#include <stdio.h>
#include <libssh/libssh.h>
#include "pssh.h"

/**
 * The command line interface for the application
 */
int main(int argc, char const* argv[])
{
   int verbosity = SSH_LOG_PROTOCOL;
   int port = 22;

   ssh_session s = ssh_new();

   ssh_options_set(s, SSH_OPTIONS_USER, "batmanpouknight");
   ssh_options_set(s, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
   ssh_options_set(s, SSH_OPTIONS_PORT, &port);

   int rc = ssh_connect(s);
   if(rc != SSH_OK)
   {
      fprintf(stderr, "Error connecting to localhost: %s\n",
              ssh_get_error(s));
      exit(-1);
   }

   enum ssh_known_hosts_e state = ssh_session_is_known_server(s);
   printf("%d\n", state);

   ssh_disconnect(s);
   ssh_free(s);
   return 0;
}
