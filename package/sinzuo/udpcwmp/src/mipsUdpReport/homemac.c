/*{
    "window.zoomLevel": 0,
    "files.autoSave": "off"
} > 
mipsel-openwrt-linux-gcc homemac.c -L./ -I./json/out/include/json/  -L./json/out/lib -ljson -luci -lubox -lpthread -o homemac

 ************************************************************************/
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include <sys/wait.h>

#include <sys/msg.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <pthread.h>
#include "b64.h"
#include "uci.h"
#include "json.h"
#include "httppost.h"

#define SERVER_PORT 8880
#define ROUTER_PORT 8880
#define HOMEDEV_PORT 8880

#define BUFFER_SIZE 1200
#define FILE_NAME_MAX_SIZE 512

#define MAXBUF 1500
#define DEV_SIZE 6
#define APP_VERSION 1

pthread_mutex_t mutex;
int readUciConfig = 1;
#define MAX_TEXT 512

#define FREE(x) \
  do            \
  {             \
    free(x);    \
    x = NULL;   \
  } while (0);

typedef int SOCKET;

typedef struct
{
  char devid[DEV_SIZE];
  int version;
  int id;
  int bufsize;
  char data[BUFFER_SIZE];
} SendPack;

typedef struct
{
  char devid[12];
  int version;
  int id;
  int bufsize;
  char data[BUFFER_SIZE]; //包含 RealTimeDate WirelessDates  NetworkDate
} RecvPack;

typedef struct
{
  char tr069state;       //tr069状态
  char cputype;          //cpu类型  1：mt7620 2：mt7628 3:ar9341
  char connectnum;       //客户端连接数量
  char aprouter;         //ap router类型  1：ap 2：router
  char equipment[16];    //硬件型号：FQa10-Tb
  char hardwaretype[16]; //设备厂家：FQ
  char softwaretype[16]; //软件版本：HBUCC-v1.7.013
  char portstate[8];     //port状态:1:连接 0：未连接
  int cpuload;           //系统负载：10 表示10%
  int memload;           //内存利用率：10 表示10%
  int upflow;            //上行流量
  int downflow;          //下行流量
  int uptime;            //在线时长'
} RealTimeDate;

typedef struct
{
  char ssid[30];
  char password[30];
  int encryption;
  int channel;
  int portel;
  int disabled;
} WirelessDate;

typedef struct
{
  int wifinum;
  WirelessDate wifidata[2];
} WirelessDates;

typedef struct
{
  int mode;
  char username[50];
  char password[50];
  char ipaddr[20];
  char network[20];
  char gateway[20];
  char dns1[20];
  char dns2[20];
} NetworkDate;

typedef struct
{
  int enable;
  int ipaddr;
  int port;
} TcpdumpData;

char deviceMac[13];
char deviceMacFu[18];

pid_t getPidByName(char *name)
{
  FILE *fp;
  char n = 0;
  pid_t pid = -1;
  char buf[10] = "";
  fp = popen(name, "r");
  if (fp != NULL)
  {
    if ((fgets(buf, 6, fp)) == NULL)
    {
      pclose(fp);
      return (pid);
    }
    pclose(fp);
    pid = atoi(buf);
  }
  return (pid);
} /* end of getpidbyname */

int commandFactoryset()
{
  system("rm -rf /overlay/*");
  system("reboot");
  return 1;
}

char *GetValByEtype(json_object *jobj, const char *sname)
{
  json_object *pval = NULL;
  enum json_type type;
  pval = json_object_object_get(jobj, sname);
  if (NULL != pval)
  {
    type = json_object_get_type(pval);
    switch (type)
    {
    case json_type_string:
      return json_object_get_string(pval);
    case json_type_int:
      return json_object_get_int(pval);

    default:
      return NULL;
    }
  }
  return NULL;
}

int GetIntByEtype(json_object *jobj, const char *sname)
{
  json_object *pval = NULL;
  enum json_type type;
  pval = json_object_object_get(jobj, sname);
  if (NULL != pval)
  {
    type = json_object_get_type(pval);
    switch (type)
    {
    case json_type_int:
      return json_object_get_int(pval);

    default:
      return 0;
    }
  }
  return 0;
}

json_object *GetValByEdata(json_object *jobj, const char *sname)
{
  json_object *pval = NULL;
  enum json_type type;
  pval = json_object_object_get(jobj, sname);
  if (NULL != pval)
  {
    type = json_object_get_type(pval);
    switch (type)
    {
    case json_type_object:
      return pval;

    case json_type_array:
      return pval;
    default:
      return NULL;
    }
  }
  return NULL;
}

char *GetValByKey(json_object *jobj, const char *sname)
{
  json_object *pval = NULL;
  enum json_type type;
  pval = json_object_object_get(jobj, sname);
  if (NULL != pval)
  {
    type = json_object_get_type(pval);
    switch (type)
    {
    case json_type_string:
      return json_object_get_string(pval);

    case json_type_object:
      return json_object_to_json_string(pval);

    default:
      return NULL;
    }
  }
  return NULL;
}

struct msg_st
{
  long int msg_type;
  char text[MAX_TEXT];
};

int recvMsgQ()
{
  int running = 1;
  int msgid = -1;
  struct msg_st data;
  long int msgtype = 1; //注意1

  //建立消息队列
  msgid = msgget((key_t)1234, 0666 | IPC_CREAT);
  if (msgid == -1)
  {
    fprintf(stderr, "msgget failed with error: %d\n", errno);
    exit(EXIT_FAILURE);
  }
  //从队列中获取消息，直到遇到end消息为止
  while (running)
  {

    if (msgrcv(msgid, (void *)&data, MAX_TEXT, msgtype, 0) == -1)
    {
      fprintf(stderr, "msgrcv failed with errno: %d\n", errno);
     
    }
    pthread_mutex_lock(&mutex); //锁定互

    printf("You wrote: %s\n", data.text);
    //遇到end结束
    readUciConfig = 1;
    pthread_mutex_unlock(&mutex); //打开互斥锁
  }
  //删除消息队列
}

static void sigHandle(int sig, struct siginfo *siginfo, void *myact)
{

  //printf("sig=%d siginfo->si_int=%d SIGALRM=%d,SIGSEGV=%d\n",sig,siginfo->si_int,SIGALRM,SIGSEGV);
  if (sig == SIGALRM)
  {
  }
  else if (sig == SIGSEGV)
  {
    sleep(1);
  }
}

static void sigInit()
{
  int i;
  struct sigaction act;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = sigHandle;

  sigaction(SIGALRM, &act, NULL);
  sigaction(SIGSEGV, &act, NULL);
}

char cliBuff[1024];

char *exeShell(char *comm)
{
  FILE *fstream = NULL;

  int errnoT = 0;

  memset(cliBuff, 0, sizeof(cliBuff));

  if (NULL == (fstream = popen(comm, "r")))
  {
    fprintf(stderr, "execute command failed: %s", strerror(errno));
    return "error";
  }
  /*    if(NULL!=fread(cliBuff,1, sizeof(cliBuff), fstream))    
    {    
        printf("exeShell zhi\n");   
    }    
    else   
    {   
        pclose(fstream);   
        return cliBuff;   
    }   
    */
  pclose(fstream);

  return cliBuff;
}

int spilt_string(char *string)
{
  int i = 0;
  const char *split = " ";
  char *p;

  p = strtok(string, split);
  while (p)
  {
    if (i == 1)
    {
      strcpy(string, p);
      //printf(" is : %s \n",string);
      return 0;
    }
    i++;
    p = strtok(NULL, split);
  }
  return -1;
}

int find_position(char *find)
{
  FILE *fp;
  char *p, buffer[128] = {0}; //初始化
  int ret;

  fp = fopen("/etc/config/wireless", "r");
  if (fp < 0)
  {
    printf("open file failed.\n");
    return -1;
  }

  //memset(buffer, 0, sizeof(buffer));
  fseek(fp, 0, SEEK_SET);
  while (fgets(buffer, 128, fp) != NULL)
  {
    p = strstr(buffer, find);
    if (p)
    {
      // printf("string is :%s \n",p);
      ret = spilt_string(p);
      if (ret == 0)
      {
        memset(find, 0, sizeof(find));
        strncpy(find, p, sizeof(p));
        return 0;
      }
    }
    memset(buffer, 0, sizeof(buffer));
  }

  fclose(fp);
  return -1;
}

int get_ower()
{
  char find[] = "Power";
  int ret;
  ret = find_position(&find);
  printf("ower --> %s", find);

  return 0;
}

int getConfig(struct uci_context *c, char *config, char *value)
{
  char buf[64];
  struct uci_ptr p;

  sprintf(buf, "pifii.server.%s", config);
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    //  sprintf(pWireless->wifidata[0].ssid, "");
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(value, p.o->v.string);
    }
    else
    {
    }
  }
  return 0;
  // printf("jiangyibo wireless get 3\n");
}

float networkConfig(struct uci_context *c, NetworkDate *pNet)
{
  char buf[128];
  struct uci_ptr p;
  memset(pNet, 0, sizeof(NetworkDate));

  sprintf(buf, "network.wan.proto");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    pNet->mode = 0;
  }
  else
  {
    if (p.o != NULL)
    {
      if (!strcmp("dhcp", p.o->v.string))
      {
        pNet->mode = 1;
      }
      else if (!strcmp("pppoe", p.o->v.string))
      {
        pNet->mode = 2;
      }
      else if (!strcmp("static", p.o->v.string))
      {
        pNet->mode = 3;
      }
      else if (!strcmp("relay", p.o->v.string))
      {
        pNet->mode = 4;
      }
      else
      {
        pNet->mode = 0;
      }
    }
    else
    {
      pNet->mode = 0;
    }
  }
  sprintf(buf, "network.wan.username");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(pNet->username, p.o->v.string);
    }
  }
  sprintf(buf, "network.wan.password");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(pNet->password, p.o->v.string);
    }
  }

  sprintf(buf, "network.wan.ipaddr");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(pNet->ipaddr, p.o->v.string);
    }
  }
  sprintf(buf, "network.wan.netmask");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(pNet->network, p.o->v.string);
    }
  }
  sprintf(buf, "network.wan.gateway");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(pNet->gateway, p.o->v.string);
    }
  }
  sprintf(buf, "network.wan.dns");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(pNet->dns1, p.o->v.string);
    }
  }
  sprintf(buf, "network.wan.dns1");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(pNet->dns2, p.o->v.string);
    }
  }
}

int middle_time(char *timespan, int hour, int min)
{
  char shour[2];
  char smin[2];
  char thour[2];
  char tmin[2];
  int s_hour;
  int s_min;
  int t_hour;
  int t_min;

  int jitime1=0;
  int jitime2=0;
  int jitime3=0;
  if (strlen(timespan) < 8)
  {
    return 0;
  }

  shour[0] = timespan[0];
  shour[1] = timespan[1];
  smin[0] = timespan[2];
  smin[1] = timespan[3];
  thour[0] = timespan[4];
  thour[1] = timespan[5];
  tmin[0] = timespan[6];
  tmin[1] = timespan[7];

  s_hour = atoi(shour);
  s_min = atoi(smin);
  t_hour = atoi(thour);
  t_min = atoi(tmin);

  jitime1 = hour*60 + min;
  jitime2 = s_hour*60 +s_min;
  jitime3 = t_hour*60 +t_min;

  if (jitime1>=jitime2&&jitime1<jitime3)
  {
    return 1;
  }
  else{
  return 0;
  }
}
char black_mac[512];
int saveEnable = 0;
int firstEnable = 0;

void black_mac_table(char *enable, char *weekdays, char *blacklist, char *timespan1, char *timespan2, char *timespan3, char *value)
{
  int index = 0;
  time_t timer;
  struct tm *tblock;
  timer = time(NULL);
  tblock = localtime(&timer);
  int enable1 = 0;
  int enable2 = 0;
  int enable3 = 0;
  char weekenable;
  printf("exec mac black 333\n");
  //  for (index = 0; index < 7; index++)
  if (enable[0] == '1')
  {
    firstEnable = 0;
    if (tblock->tm_wday == 0)
    {
      weekenable = weekdays[6];
    }
    else
    {
      weekenable = weekdays[tblock->tm_wday - 1];
    }

    if (weekenable == '1')
    {

      printf("exec mac black 333 4444\n");
      enable1 = middle_time(timespan1, tblock->tm_hour, tblock->tm_min);
      enable2 = middle_time(timespan2, tblock->tm_hour, tblock->tm_min);
      enable3 = middle_time(timespan3, tblock->tm_hour, tblock->tm_min);
      if (enable1 == 1 || enable2 == 1 || enable3 == 1)
      {
        if (!strcmp(black_mac, blacklist))
        {
          if (saveEnable == 1)
          {
            printf("已经保存状态，不要写表 %s\n", black_mac);
          }
          else
          {
            system("blackmac ok&");
            printf("写表成功 %s\n", black_mac);
          }
        }
        else
        {
          strcpy(black_mac, blacklist);
          system("blackmac ok&");
          printf("初次写表\n");
        }
        saveEnable = 1;
        return;
      }
      else
      {
        if (saveEnable == 1)
        {
          system("blackmac &");
          printf("exec mac 清空表\n");
        }
        else
        {
          printf("不需要 清空表\n");
        }
        saveEnable = 0;
      }
    }
    else
    {
      if (saveEnable == 1)
      {
        system("blackmac &");
        printf("exec mac 清空表\n");
        saveEnable = 0;
      }
    }
  }
  else
  {
    saveEnable=0;
    if (firstEnable == 0)
    {
      system("blackmac &");
      printf("exec mac 清空表\n");
      firstEnable = 1;
    } else {

    }
  }
  return;
}

int main(int argc, char *argv[])
{
  int commandkey = 0;
  int uptime = 0;
  int length;
  int rc;
  int commandId;
  int i;
  int ret;
  int len = 0;
  int temp = 1;
  int inSpeed = 0, outSpeed = 0;
  int looptimes = 10;
  int homeOrRoute = 0;

  struct uci_context *c;
  pthread_t id1, id2;
  char blacklist[512];
  char enable[4];
  char timespan1[16];
  char timespan2[16];
  char timespan3[16];
  char weekdays[16];

  pthread_mutex_init(&mutex, NULL);
  c = uci_alloc_context();
  getConfig(c, "enable", enable);
  getConfig(c, "weekdays", weekdays);
  getConfig(c, "blacklist", blacklist);
  getConfig(c, "timespan1", timespan1);
  getConfig(c, "timespan2", timespan2);
  getConfig(c, "timespan3", timespan3);
  //   printf("jiangyibo net\n");
  uci_free_context(c);

  ret = pthread_create(&id1, NULL, (void *)recvMsgQ, NULL); //创建线程1
  if (ret != 0)
  {
    printf("create pthread error !\n");
  }
  else
  {
  }

  while (1)
  {
    printf("jiangyibo while\n");
    pthread_mutex_lock(&mutex); //锁定互斥锁

    if (readUciConfig == 1)
    {
      c = uci_alloc_context();
      getConfig(c, "enable", enable);
      getConfig(c, "weekdays", weekdays);
      getConfig(c, "blacklist", blacklist);
      getConfig(c, "timespan1", timespan1);
      getConfig(c, "timespan2", timespan2);
      getConfig(c, "timespan3", timespan3);

      uci_free_context(c);
      readUciConfig = 0;
    }

    black_mac_table(enable,weekdays, blacklist, timespan1, timespan2, timespan3, black_mac);

    pthread_mutex_unlock(&mutex); //打开互斥锁
    temp = 2;
    sleep(2);

    //break;
  }

  printf("cucuo \n");

  return 0;
}
