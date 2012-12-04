#ifndef __publish_h
#define __publish_h

#include <arpa/inet.h>
#include <getopt.h>
#include "hpfeeds.h"
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#define MAXLEN 32768

typedef enum {
S_INIT,
S_AUTH,
S_SUBSCRIBE,
S_PUBLISH,
S_RECVMSGS,
S_ERROR,
S_TERMINATE
} session_state_t;


typedef enum {
C_SUBSCRIBE,
C_PUBLISH,
C_UNKNOWN } cmd_t;

void* publish(void *buf);
u_char *read_msg(int s);
void readConfig(char *conf_path,char *conf_name,char *config_buff);
char *url_encode(char *str);
#endif
