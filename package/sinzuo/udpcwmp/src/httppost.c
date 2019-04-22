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



#include "httppost.h"

int postnameserver(int *value, char *NET_IP)
{
  //获取联网状态
  struct hostent *host;
  int inaddr = 1;
  struct in_addr *ipaddr;
  /*判断是主机名还是ip地址*/
  if ((inaddr = inet_addr(NET_IP) )== INADDR_NONE)
  {
    if ((host = gethostbyname(NET_IP)) == NULL) /*是主机名*/
    {
      printf("post dns chucuo\n");
      return 0;
    }
    ipaddr = (struct in_addr *)host->h_addr;
    *value = (ipaddr->s_addr);
  }
  else /*是ip地址*/
  {
    *value = inaddr;
  }
  return 1;
}

int httppost(char *bufMsg, int length)
{
        int sockfd, ret, i, h;
        struct sockaddr_in servaddr;
        char str1[4096],  buf[1024], *str;
        int  postPort;
        socklen_t len;
        int   recvLeng=0;
        fd_set t_set1;
        struct timeval tv;
        struct sockaddr_in server_addr;
        bzero(&server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        socklen_t server_addr_length = sizeof(server_addr);

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
                printf("创建网络连接失败,本线程即将终止---socket error!\n");
                return -1;
        };

        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        postPort = atoi(httpPostServerPort);
        servaddr.sin_port = htons(postPort);

        struct timeval timeout = {2, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

  //      if (inet_pton(AF_INET, httpPostServerIp , &servaddr.sin_addr) <= 0)
        if(postnameserver(&(servaddr.sin_addr.s_addr),httpPostServerIp)==0)
        {
                printf("创建网络连接失败,本线程即将终止--inet_pton error!\n");
                return -1;
        }

        if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        {
                printf("连接到服务器失败,connect error!\n");
                return -1;
        }
        printf("与远端建立了连接\n");

  //      memset(str2, 0, 4096);
  //      strcat(str2, bufMsg);
        str = (char *)malloc(128);
        len = strlen(bufMsg);
        sprintf(str, "%d", len);

        memset(str1, 0, 4096);
        strcat(str1, "POST ");
        strcat(str1, httpPostServerPath);
        strcat(str1, " HTTP/1.1\n");
        strcat(str1, "Host: www.cnihome.net\n");
        strcat(str1, "Content-Type: application/json;charset=utf-8\n");
        strcat(str1, "Content-Length: ");
        strcat(str1, str);
        strcat(str1, "\n\n");
        //str2的值为post的数据
        strcat(str1, bufMsg);
        strcat(str1, "\r\n\r\n");
        printf("%s\n", str1);

        ret = write(sockfd, str1, strlen(str1));
        if (ret < 0)
        {
                printf("发送失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
                return -1;
        }
        else
        {
                printf("消息发送成功，共发送了%d个字节！\n\n", ret);
        }
        free(str);

        if (debug_mode > 0)
        {
                memset(buf, 0, 1024);

                if ((recvLeng = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&server_addr, &server_addr_length)) > 0)
                {
                        printf("消息接受成功，共收了%d个字节！\n\n", recvLeng);
                        close(sockfd);
                        return 1;
                }
                else
                {
                        close(sockfd);
                        return -1;
                }
        }else {

        close(sockfd);
        return 1;
        }
        /*

        FD_ZERO(&t_set1);
        FD_SET(sockfd, &t_set1);

        tv.tv_sec = 2;
        tv.tv_usec = 0;
        h = 0;

        while (1)
        {

                printf("--------------->3");
                h = select(sockfd + 1, &t_set1, NULL, NULL, &tv);
                printf("--------------->3");
                //if (h == 0) continue;
                if (h == -1)
                {
                        close(sockfd);
                        printf("在读取数据报文时SELECT检测到异常，该异常导致线程终止！\n");
                        return -1;
                };
                if (FD_ISSET(sockfd, &t_set1))
                {
                        memset(buf, 0, 4096);
                        i = read(sockfd, buf, 4095);
                        if (i == 0)
                        {
                                close(sockfd);
                                printf("读取数据报文时发现远端关闭，该线程终止！\n");
                                return -1;
                        }
                        printf("%s\n", buf);
                        close(sockfd);
                        printf("send ok\n");
                        return 0;
                }
                else
                {
                        close(sockfd);
                        return -1;
                }
        }
*/

        return 0;
}


int httppostGetValue(char *bufMsg, int length,int check,char *recvBuf)
{
        int sockfd, ret, i, h;
        struct sockaddr_in servaddr;
        char str1[4096],  buf[1024], *str;
        int  postPort;
        socklen_t len;
        int   recvLeng=0;
        fd_set t_set1;
        struct timeval tv;
        struct sockaddr_in server_addr;
        bzero(&server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        socklen_t server_addr_length = sizeof(server_addr);

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
                printf("创建网络连接失败,本线程即将终止---socket error!\n");
                return -1;
        };

        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        postPort = atoi(httpPostServerPort);
        servaddr.sin_port = htons(postPort);

        struct timeval timeout = {2, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

  //      if (inet_pton(AF_INET, httpPostServerIp , &servaddr.sin_addr) <= 0)
        if(postnameserver(&(servaddr.sin_addr.s_addr),httpPostServerIp)==0)
        {
                printf("创建网络连接失败,本线程即将终止--inet_pton error!\n");
                return -1;
        }

        if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        {
                printf("连接到服务器失败,connect error!\n");
                return -1;
        }
        printf("与远端建立了连接\n");

  //      memset(str2, 0, 4096);
  //      strcat(str2, bufMsg);
        str = (char *)malloc(128);
        len = strlen(bufMsg);
        sprintf(str, "%d", len);

        memset(str1, 0, 4096);
        strcat(str1, "POST ");
        strcat(str1, httpPostServerPath);
        strcat(str1, " HTTP/1.1\n");
        strcat(str1, "Host: www.cnihome.net\n");
        strcat(str1, "Content-Type: application/json;charset=utf-8\n");
        strcat(str1, "Content-Length: ");
        strcat(str1, str);
        strcat(str1, "\n\n");
        //str2的值为post的数据
        strcat(str1, bufMsg);
        strcat(str1, "\r\n\r\n");
        printf("%s\n", str1);

        ret = write(sockfd, str1, strlen(str1));
        if (ret < 0)
        {
                printf("发送失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
                return -1;
        }
        else
        {
                printf("消息发送成功，共发送了%d个字节！\n\n", ret);
        }
        free(str);

        if (debug_mode > 0||check == 1)
        {

                memset(buf, 0, 1024);

                if ((recvLeng = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&server_addr, &server_addr_length)) > 0)
                {
                        if(check == 1 && recvBuf != NULL)
                        {
                           strcpy(recvBuf,buf);
                        }
                        printf("消息接受成功，共收了%d个字节！\n\n", recvLeng);
                        close(sockfd);
                        return 1;
                }
                else
                {
                        close(sockfd);
                        return -1;
                }
        }else {

        close(sockfd);
        return 1;
        }
        return 0;
}