/*
  hpclient.c
  Copyright (C) 2011 The Honeynet Project
  Copyright (C) 2011 Tillmann Werner, tillmann.werner@gmx.de

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "publish.h"
#include <glib.h>

session_state_t session_state;	// global session state
char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}
char *url_encode(char *str) {
  char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
  while (*pstr) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
      *pbuf++ = *pstr;
    else if (*pstr == ' ')
      *pbuf++ = '+';
    else
      *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}
u_char *read_msg(int s) {
	u_char *buffer;
	u_int32_t msglen;

	if (read(s, &msglen, 4) != 4) {
		perror("read()");
		return NULL;
	}

	if ((buffer = g_malloc0(ntohl(msglen))) == NULL) {
		printf ("malloc() message buffer error");
		return NULL;
	}

	*(u_int32_t *) buffer = msglen;
	msglen = ntohl(msglen);

	if (read(s, buffer + 4, msglen - 4) != (msglen - 4)) {
		perror("read()");
		return NULL;
	}

	return buffer;
}
void readConfig(char *conf_path,char *conf_name,char *config_buff)
{
    char config_linebuf[256];
    char line_name[40];
    char exchange_buf[256];
    char *config_sign = "=";
    char *leave_line;
    FILE *f;
    f = fopen(conf_path,"r");
    if(f == NULL)
    {
        printf("OPEN CONFIG FALID\n");
        return ;
    }
    fseek(f,0,SEEK_SET);
    while(fgets(config_linebuf,256,f) != NULL)
    {
        if(strlen(config_linebuf) < 3) //判断是否是空行
        {
            continue;
        }
        if (config_linebuf[strlen(config_linebuf)-1] == 10) //去除最后一位是\n的情况
        {

            memset(exchange_buf,0,sizeof(exchange_buf));
            strncpy(exchange_buf,config_linebuf,strlen(config_linebuf)-1);
            memset(config_linebuf,0,sizeof(config_linebuf));
            strcpy(config_linebuf,exchange_buf);
        }
        memset(line_name,0,sizeof(line_name));
        leave_line = strstr(config_linebuf,config_sign);
        if(leave_line == NULL)                            //去除无"="的情况
        {
            continue;
        }
        int leave_num = leave_line - config_linebuf;
        strncpy(line_name,config_linebuf,leave_num);
        if(strcmp(line_name,conf_name) ==0)
        {
            strncpy(config_buff,config_linebuf+(leave_num+1),strlen(config_linebuf)-leave_num-1);
            break;
        }
        if(fgetc(f)==EOF)
        {
            break;
        }
        fseek(f,-1,SEEK_CUR);
        memset(config_linebuf,0,sizeof(config_linebuf));
    }
    fclose(f);

}

void* publish(void *buff) {
	u_char *buf=(u_char *)malloc((strlen(buff)+2)*sizeof(u_char));
	strcpy((char *)buf,(char *)buff);
	//printf("\n%d %d %d\n",(int)strlen(buff),(int)strlen((char*)buf),(int)sizeof(buf));
	printf("bistream : %s",(char *)buf);
	cmd_t hpfdcmd;
	hpf_msg_t *msg;
	hpf_chunk_t *chunk;
	u_char *data;
	char *errmsg;
	int s;
	struct hostent *he;

	u_int32_t nonce = 0;

	hpfdcmd=C_UNKNOWN;
	msg = NULL;

	hpfdcmd = C_PUBLISH;
	char *cfgname="/etc/dionaea/hpfeeds.cfg";
	u_char channel[50] = "dionaea.bistream";
	char hostname[50]="192.168.232.139";
	u_char ident[50] ="ww3ee@hp1";
	u_char secret[50] ="7w35rippuhx7704h";
	char port[10];
	readConfig(cfgname,"HOST",(char *)hostname);
	readConfig(cfgname,"PORT",(char *)port);
	readConfig(cfgname,"IDENT",(char *)ident);
	readConfig(cfgname,"SECRET",(char *)secret);
	readConfig(cfgname,"CHANNEL",(char *)channel);

	if ((he = gethostbyname(hostname)) == NULL) {
		perror("gethostbyname()");
		free(buf);
		return NULL ;
	}

	if (he->h_addrtype == AF_INET) {
		struct sockaddr_in host;
		bzero(&host, sizeof(host));
		host.sin_family = AF_INET;
		host.sin_addr = *(struct in_addr *) he->h_addr;
		host.sin_port = htons(strtoul(port, 0, 0));
		// connect to broker
		if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
			perror("socket()");
			free(buf);
			return NULL ;
		}
		fprintf(stderr, "connecting to %s:%u\n", inet_ntoa(host.sin_addr), ntohs(host.sin_port));
		if (connect(s, (struct sockaddr *) &host, sizeof(host)) == -1) {
			printf("connect to server error");
			free(buf);
			return NULL;
		}
	}
	else if (he->h_addrtype == AF_INET6) {
		struct sockaddr_in6 host;
		bzero(&host, sizeof(host));
		host.sin6_family = AF_INET6;
		if ( inet_pton(AF_INET6, he->h_addr, &host.sin6_addr) < 0 ) {
			perror("inet_pton()");
			free(buf);
			return NULL;
		 }
		host.sin6_port = htons(strtoul(port, 0, 0));
		// connect to broker
		if ((s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1) {
			perror("socket()");
			free(buf);
			return NULL;
		}
		//fprintf(stderr, "connecting to %s:%u\n", inet_ntoa(host.sin6_addr), ntohs(host.sin6_port));
		if (connect(s, (struct sockaddr *) &host, sizeof(host)) == -1) {
			printf("connect to server error");
			free(buf);
			return NULL;
		}
	}
	else{
		fprintf(stderr, "Unsupported address type\n");
		free(buf);
		return NULL;
	}




	session_state = S_INIT; // initial session state

	// this is our little session state machine
	for (;;) switch (session_state) {
	case S_INIT:
		// read info message
		if ((data = read_msg(s)) == NULL) break;
		msg = (hpf_msg_t *) data;

		switch (msg->hdr.opcode) {
		case OP_INFO:

			chunk = hpf_msg_get_chunk(data + sizeof(msg->hdr), ntohl(msg->hdr.msglen) - sizeof(msg->hdr));
			if (chunk == NULL) {
				fprintf(stderr, "invalid message format\n");
				free(buf);
				return NULL;
			}

			nonce = *(u_int32_t *) (data + sizeof(msg->hdr) + chunk->len + 1);

			session_state = S_AUTH;

			free(data);

			break;
		case OP_ERROR:
			session_state = S_ERROR;
			break;
		default:
			fprintf(stderr, "unknown server message (type %u)\n", msg->hdr.opcode);
			free(buf);
			return NULL;
		}

		break;
	case S_AUTH:
		// send auth message
		fprintf(stderr, "sending authentication...\n");
		msg = hpf_msg_auth(nonce, (u_char *) ident, strlen((const char *)ident), (u_char *) secret, strlen((const char *)secret));

		if (write(s, (u_char *) msg, ntohl(msg->hdr.msglen)) == -1) {
			perror("write()");
			free(buf);
			return NULL;
		}
		hpf_msg_delete(msg);

		if (hpfdcmd == C_SUBSCRIBE)
			session_state = S_SUBSCRIBE;
		else
			session_state = S_PUBLISH;
		break;
	case S_PUBLISH:
		// send publish message
		fprintf(stderr, "publish bistream  ...\n");
		int len=strlen((const char *)buf);
		//printf("%s",buf);
		msg = hpf_msg_publish((u_char *) ident, strlen((const char *)ident), (u_char *) channel, strlen((const char *)channel),(u_char *)buf,len);
		if (write(s, (u_char *) msg, ntohl(msg->hdr.msglen)) == -1) {
			perror("write()");
			free(buf);
			return NULL;
		}
		hpf_msg_delete(msg);
		free(buf);
		return NULL;
		break;
	case S_ERROR:
		if (msg) {
			// msg is still valid
			if ((errmsg = calloc(1, msg->hdr.msglen - sizeof(msg->hdr))) == NULL) {
				perror("calloc()");
				free(buf);
				return NULL;
			}
			memcpy(errmsg, msg->data, msg->hdr.msglen - sizeof(msg->hdr));

			fprintf(stderr, "server error: '%s'\n", errmsg);
			free(errmsg);
			free(msg);
		}

		session_state = S_TERMINATE;
		break;
	case S_TERMINATE:
		fprintf(stderr, "terminated.\n");
		close(s);
		free(buf);
		return NULL;
	default:
		fprintf(stderr, "unknown session state\n");
		close(s);
		free(buf);
		return NULL;
	}

	close(s);
	free(buf);
	return NULL;
}

/*
int main(int argc, char *argv[])
{
	u_char data[20]="char data";
	publish(data);
}*/
