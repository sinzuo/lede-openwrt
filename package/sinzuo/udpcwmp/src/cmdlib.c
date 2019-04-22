#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>




int read_memory(char *shellcmd, char *out, int size) {

        FILE *stream;
        char buffer[128];
        memset(buffer, 0, sizeof(buffer));

        stream = popen(shellcmd, "r");
        if(stream != NULL){
        fread(buffer, sizeof(char), sizeof(buffer), stream);
        pclose(stream);

                memcpy(out, buffer, strlen(buffer) + 1);

                return 1;
        } else {
                out[0] = '\0';

        }

        return 0;
}

char *get_attr_with_end(char *data, char *dataEnd, char *name, char *value, char *endString) {

        char *pIndex = NULL;
        char *pTail = NULL;

        // 初始化为空字符串
        value[0] = '\0';
        if (data == NULL) {
                return NULL;
        }

        do {
                char aName[100];
                int name_len;
                name_len = strlen(name);
                sprintf(aName, " %s", name);
                //printf("%s\n", aName);
                pIndex = strstr(data, aName);
                //printf(pIndex);
                if(pIndex == NULL)
                        pIndex = strstr(data, name);
                else
                {
                        name_len ++;
                        //printf("%s\n", pIndex);
                }
                // write_log_file("pIndex\n");

                if (pIndex == NULL || (dataEnd != NULL && pIndex > dataEnd)) {
                        strcpy(value, "NULL");

                        return NULL;
                }

                pIndex += name_len;

                if (*pIndex == '=' || *pIndex == ':' || *pIndex == ' ') {
                        pIndex++;
                        // 首位为空格时去掉
                        while (*pIndex == ' ') {
                                pIndex++;
                        }
                        break;
                } else {
                        data = pIndex;
                }
        } while (1);

    pTail = strstr(pIndex, endString);
        if (pTail == NULL) {
                strcpy(value, "NULL");

                return NULL;
        }
        // write_log_file("pTail\n");

        // trim double quotes
        if (*pIndex == '"' && *(pTail - 1) == '"') {
                pIndex++;
                pTail--;
        }

    memcpy(value, pIndex, pTail - pIndex);
        value[pTail - pIndex] = '\0';

        // write_log_file(name);
        // write_log_file(value);

        return pTail;
}


char *get_attr(char *data, char *name, char *value, char *endString) {
        return get_attr_with_end(data, NULL, name, value, endString);
}

char *get_attr_by_line(char *data, char *name, char *value) {
        return get_attr(data, name, value, "\n");
}

int get_single_config_attr(char *name, char *value) {

        char shellcmd[128], buffer[128];
        sprintf(shellcmd, "%s | grep %s=", 128, name);
        if (read_memory(shellcmd, buffer, sizeof(buffer)) == 1) {
                if (get_attr_by_line(buffer, name, value) == NULL) {
                        value[0] = '\0';
                }
        } else {
                value[0] = '\0';
        }

        return 1;
}

//去除结尾的空白字符
void util_strip_traling_spaces( char* one_string )
{
	char* tmp=one_string;
	int length=strlen(tmp);
	while(
			length
			&&(
				( tmp[ length-1 ] == '\r' )
				|| ( tmp[ length-1 ] == '\n' )
				|| ( tmp[ length-1 ] == '\t' )
				|| ( tmp[ length-1 ] == ' ' )
			)
		)
	{
		tmp[ length-1 ]=0;
		length--;
	}
}
