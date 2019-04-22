/*{
    "window.zoomLevel": 0,
    "files.autoSave": "off"
} > 
mipsel-openwrt-linux-gcc tcpTrClient.c -L./ -luci -lubox  -o tcpreport
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

#include <sys/types.h>
#include <sys/ipc.h>
#include "uci.h"



#define BUFFER_SIZE 1200
#define FILE_NAME_MAX_SIZE 512

#define MAXBUF 1500
#define DEV_SIZE 6
#define APP_VERSION 1
#define SERVER_IP   "192.168.2.198" //tz.pifii.com
#define SERVER_PORT 8880
#define BYTE char

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

char device_mac[6];

//以下是 Base64.h 的内容:

size_t Base64_Decode(char *pDest, const char *pSrc, size_t srclen);
size_t Base64_Encode(char *pDest, const char *pSrc, size_t srclen);

//以下是 Base64.cpp 的内容:

BYTE Decode_GetByte(char c);
char Encode_GetChar(BYTE num);

//===================================
//    Base64 解码
//===================================
BYTE Decode_GetByte(char c)
{
  if (c == '+')
    return 62;
  else if (c == '/')
    return 63;
  else if (c <= '9')
    return (BYTE)(c - '0' + 52);
  else if (c == '=')
    return 64;
  else if (c <= 'Z')
    return (BYTE)(c - 'A');
  else if (c <= 'z')
    return (BYTE)(c - 'a' + 26);
  return 64;
}

//解码
size_t Base64_Decode(char *pDest, const char *pSrc, size_t srclen)
{
  BYTE input[4];
  size_t i, index = 0;
  for (i = 0; i < srclen; i += 4)
  {
    //byte[0]
    input[0] = Decode_GetByte(pSrc[i]);
    input[1] = Decode_GetByte(pSrc[i + 1]);
    pDest[index++] = (input[0] << 2) + (input[1] >> 4);

    //byte[1]
    if (pSrc[i + 2] != '=')
    {
      input[2] = Decode_GetByte(pSrc[i + 2]);
      pDest[index++] = ((input[1] & 0x0f) << 4) + (input[2] >> 2);
    }

    //byte[2]
    if (pSrc[i + 3] != '=')
    {
      input[3] = Decode_GetByte(pSrc[i + 3]);
      pDest[index++] = ((input[2] & 0x03) << 6) + (input[3]);
    }
  }

  //null-terminator
  pDest[index] = 0;
  return index;
}

//===================================
//    Base64 编码
//===================================
char Encode_GetChar(BYTE num)
{
  return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
         "abcdefghijklmnopqrstuvwxyz"
         "0123456789"
         "+/="[num];
}

//编码
size_t Base64_Encode(char *pDest, const char *pSrc, size_t srclen)
{
  BYTE input[3], output[4];
  size_t i, index_src = 0, index_dest = 0;
  for (i = 0; i < srclen; i += 3)
  {
    //char [0]
    input[0] = pSrc[index_src++];
    output[0] = (BYTE)(input[0] >> 2);
    pDest[index_dest++] = Encode_GetChar(output[0]);

    //char [1]
    if (index_src < srclen)
    {
      input[1] = pSrc[index_src++];
      output[1] = (BYTE)(((input[0] & 0x03) << 4) + (input[1] >> 4));
      pDest[index_dest++] = Encode_GetChar(output[1]);
    }
    else
    {
      output[1] = (BYTE)((input[0] & 0x03) << 4);
      pDest[index_dest++] = Encode_GetChar(output[1]);
      pDest[index_dest++] = '=';
      pDest[index_dest++] = '=';
      break;
    }

    //char [2]
    if (index_src < srclen)
    {
      input[2] = pSrc[index_src++];
      output[2] = (BYTE)(((input[1] & 0x0f) << 2) + (input[2] >> 6));
      pDest[index_dest++] = Encode_GetChar(output[2]);
    }
    else
    {
      output[2] = (BYTE)((input[1] & 0x0f) << 2);
      pDest[index_dest++] = Encode_GetChar(output[2]);
      pDest[index_dest++] = '=';
      break;
    }

    //char [3]
    output[3] = (BYTE)(input[2] & 0x3f);
    pDest[index_dest++] = Encode_GetChar(output[3]);
  }
  //null-terminator
  pDest[index_dest] = 0;
  return index_dest;
}

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

int read_mac()
{
  FILE *fp = NULL;
  char ch;
  char bufexe[128];
  char buffstr[4096];

  if ((fp = fopen("/dev/mtdblock2", "r")) == NULL)
  {
    printf("file cannot be opened/n");
  }
  fgets(buffstr, 32, fp);
  //  printf("jiang %02X %02X %02X %02X %02X %02X\n", buffstr[4], buffstr[5], buffstr[6], buffstr[7], buffstr[8], buffstr[9]);

  device_mac[0] = buffstr[4];
  device_mac[1] = buffstr[5];
  device_mac[2] = buffstr[6];
  device_mac[3] = buffstr[7];
  device_mac[4] = buffstr[8];
  device_mac[5] = buffstr[9];
  fclose(fp);
  fp = NULL;

  return 0;
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

int getCpuUsage()
{
  float sys_usage;
  float user_usage;
#define CPU_FILE_PROC_STAT "/proc/stat"
  FILE *fp = NULL;
  char tmp[10];
  unsigned long user, sys, nice, idle, total;

  fp = fopen(CPU_FILE_PROC_STAT, "r");
  if (fp == NULL)
  {
    return 10;
  }
  fscanf(fp, "%s %lu %lu %lu %lu", tmp, &user, &nice, &sys, &idle);

  fclose(fp);
  total = user + sys + nice + idle;
  if (total > 0)
  {
    sys_usage = sys * 100.0 / total;
    user_usage = user * 100.0 / total;
    return (int)((sys_usage + user_usage));
  }
  else
  {
    sys_usage = 0;
    user_usage = 0;
    return 10;
  }
  //cpu_rate = (1-idle/total)*100;

  return 0;
}

struct mem_usage_t
{
  unsigned long total;
  unsigned long used;
  unsigned long free;
  unsigned long shared;
  unsigned long buffers;
  unsigned long cached;
};

int getMemUsage()
{
  FILE *fp = NULL;
  struct mem_usage_t memge;
  struct mem_usage_t *usage;
  usage = &memge;
  char tmp[1024];
  char str[128];
  char str1[128];
  int total = 0, memfree = 0;
  int index = 0;
  char *t;

  fp = fopen("/proc/meminfo", "r");
  if (fp == NULL)
  {
    return 10;
  }

  while ((fgets(tmp, 1024, fp)) != NULL)
  {
    if (strstr(tmp, "MemTotal:"))
    {
      index = 0;
      t = strtok(tmp, " ");
      while (t != NULL)
      {
        index++;
        if (index == 2)
        {
          total = atoi(t);
          //  printf("%s\n", t);
        }
        t = strtok(NULL, " ");
      }
    }
    else if (strstr(tmp, "MemFree:"))
    {
      index = 0;
      t = strtok(tmp, " ");
      while (t != NULL)
      {
        index++;
        if (index == 2)
        {
          //   printf("%s\n", t);
          memfree = atoi(t);
        }
        t = strtok(NULL, " ");
      }
    }
    else
    {

      break;
    }
  }
  // printf("jiangyibo mem %d \n",(int)((memfree*100.0)/total));

  return (int)((memfree * 100.0) / total);
}

int getRunTime()
{

  FILE *fp = NULL;
  char tmp[128];
  int timeBuf = 0;

  fp = popen("cat /proc/uptime | awk -F \".\" '{ print $1 }'", "r");
  if (fp == NULL)
  {
    return 0;
  }
  if (fread(tmp, 1, 128, fp) > 0)
  {
    timeBuf = atoi(tmp);
  }
  else
  {
  }
  pclose(fp);
  //  printf("jiangyibo getRunTime %d\n", timeBuf);
  return timeBuf;
}

int getPortState(char *portstate)
{

  FILE *fp = NULL;
  char tmp[1024];
  int timeBuf = 0;
  char *port = portstate;
  int i;

  int portResult = 0;

  fp = popen("swconfig dev switch0 show 2>/dev/null", "r");
  if (fp == NULL)
  {
    return 0;
  }

  while ((fgets(tmp, 1024, fp)) != NULL)
  {
    if (strstr(tmp, "link: port:0 link:up"))
    {
      port[0] = 1;
    }
    else if (strstr(tmp, "link: port:1 link:up"))
    {
      port[1] = 1;
    }
    else if (strstr(tmp, "link: port:2 link:up"))
    {
      port[2] = 1;
    }
    else if (strstr(tmp, "link: port:3 link:up"))
    {
      port[3] = 1;
    }
    else if (strstr(tmp, "link: port:4 link:up"))
    {
      port[4] = 1;
    }
  }

  pclose(fp);

  return portResult;
}

int getDeviceSpeed(int *total, int *used)
{

  FILE *fp = NULL;
  char tmp[128];
  int timeBuf = 0;

  fp = popen("ifconfig br-lan|grep bytes|awk -F 'bytes:' '{print $2,$3}'|awk '{print $1,$5}'", "r");
  if (fp == NULL)
  {
    return 0;
  }
  fscanf(fp, "%lu %lu", total, used);
  //  printf("jiangyibo getRunTime %d %d\n", *total, *used);
  pclose(fp);
  return 0;
}

int getConnectNum(char *conn)
{

  FILE *fp = NULL;
  char tmp[128];
  int timeBuf = 0;
  int total;

  fp = popen("iwinfo ra0 a|grep RX|wc -l", "r");
  if (fp == NULL)
  {
    return 0;
  }
  fscanf(fp, "%lu", &total);
  //  printf("jiangyibo getConnectNum %d\n", total);
  pclose(fp);
  *conn = (char)total;
  return 0;
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

float wirelessConfig(struct uci_context *c, WirelessDates *pWireless)
{
  char buf[128];
  struct uci_ptr p;
  memset(pWireless, 0, sizeof(WirelessDates));
  sprintf(buf, "wireless.@wifi-iface[0].ssid");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    //  sprintf(pWireless->wifidata[0].ssid, "");
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(pWireless->wifidata[0].ssid, p.o->v.string);
    }
    else
    {
    }
  }
  // printf("jiangyibo wireless get \n");
  sprintf(buf, "wireless.@wifi-iface[0].key");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(pWireless->wifidata[0].password, p.o->v.string);
    }
  }
  sprintf(buf, "wireless.@wifi-iface[0].encryption");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    pWireless->wifidata[0].encryption = 0;
  }
  else
  {
    if (p.o != NULL)
    {
      if (!strcmp("psk2+aes", p.o->v.string))
      {
        pWireless->wifidata[0].encryption = 2;
      }
      else if (!strcmp("psk2", p.o->v.string))
      {
        pWireless->wifidata[0].encryption = 1;
      }
      else
      {
        pWireless->wifidata[0].encryption = 3;
      }
    }
  }
  sprintf(buf, "wireless.ra0.channel");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    pWireless->wifidata[0].channel = 13;
  }
  else
  {
    if (p.o != NULL)
    {
      if (!strcmp(p.o->v.string, "auto"))
      {
        pWireless->wifidata[0].channel = 100;
      }
      else
      {
        //    printf("jiangyibo wireless get 223388 %d \n", p.o);
        pWireless->wifidata[0].channel = atoi(p.o->v.string);
      }
    }
  }
  sprintf(buf, "wireless.@wifi-iface[0].portel");
  if (uci_lookup_ptr(c, &p, buf, true))
  {
    //   printf("jiangyibo wireless get 23\n");
    pWireless->wifidata[0].portel = 0;
  }
  else
  {
    if (p.o != NULL)
    {
      pWireless->wifidata[0].portel = atoi(p.o->v.string);
    }
    else
    {
      pWireless->wifidata[0].portel = 0;
    }
  }
  sprintf(buf, "wireless.@wifi-iface[0].disabled");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    pWireless->wifidata[0].disabled = 0;
  }
  else
  {
    if (p.o != NULL)
    {
      pWireless->wifidata[0].disabled = atoi(p.o->v.string);
    }
    else
    {
      pWireless->wifidata[0].disabled = 0;
    }
  }
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

int main(int argc, char *argv[])
{
  sigInit();
  read_mac();

  int id = 0;
  SendPack sendmsg;
  int index = 0;
  char *p;
  RealTimeDate *pReal;
  WirelessDates *pWireless;
  NetworkDate *pNet;

  struct uci_context *c;
  int client_socket_fd = 0;
  int len = 0;
  int temp = 1;
  int inSpeed = 0, outSpeed = 0;
  int looptimes = 10;

  pReal = sendmsg.data;
  pWireless = sendmsg.data + sizeof(RealTimeDate);
  pNet = sendmsg.data + sizeof(RealTimeDate) + sizeof(WirelessDates);

  sendmsg.version = APP_VERSION;
  sendmsg.id = 222;
  memcpy(sendmsg.devid, device_mac, 6);
  sendmsg.bufsize = 1500;
  sprintf(pReal->equipment, "TZ");
  sprintf(pReal->hardwaretype, "PF308-TZ-H");
  sprintf(pReal->softwaretype, "1.6.12");

  pReal->aprouter = 1;
  pWireless->wifinum = 1;

  sendmsg.version = APP_VERSION;

  /* 服务端地址 */
  struct sockaddr_in server_addr;
  bzero(&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  if (argc == 1)
  {
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
  }
  else if (argc == 2)
  {
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);
  }
  server_addr.sin_port = htons(SERVER_PORT);
  socklen_t server_addr_length = sizeof(server_addr);
start:
  /* 创建socket */
  client_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (client_socket_fd < 0)
  {
    perror("Create Socket Failed:");
    exit(1);
  }

  if (connect(client_socket_fd, (struct sockaddr *)&server_addr, server_addr_length) < 0)
  {
    perror("connect error:");
    close(client_socket_fd);
    sleep(20);
    goto start;
  }
  /*
  struct timeval timeout = {5, 0};
  setsockopt(client_socket_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
  setsockopt(client_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
  */
  RecvPack pack_info;

  while (1)
  {
    //  printf("jiangyibo while\n");
    if (getPidByName("pidof freecwmpd") < 1)
      pReal->tr069state = 4;
    else
      pReal->tr069state = 3;
    if (looptimes++ >= 10)
    {
      looptimes = 0;
      getPortState(pReal->portstate);
      pReal->cpuload = getCpuUsage();
      pReal->memload = getMemUsage();
      getDeviceSpeed(&pReal->upflow, &pReal->downflow);
      pReal->uptime = getRunTime();
      pReal->cputype = 1;
      getConnectNum(&pReal->connectnum);
    }

    c = uci_alloc_context();
    //   printf("jiangyibo wireless 22\n");
    wirelessConfig(c, pWireless);
    //   printf("jiangyibo wireless\n");
    networkConfig(c, pNet);
    //   printf("jiangyibo net\n");
    uci_free_context(c);

    printf("jiangyibo send 111 ok\n");

    memset((char *)&sendmsg, 0, sizeof(SendPack));

    strcpy((char *)&sendmsg, "jiangyibowullllllll");

    send(client_socket_fd, (char *)&sendmsg, sizeof(SendPack), 0);

    /* 从服务器接收数据，并写入文件 */
    if ((len = read(client_socket_fd, (char *)&pack_info, sizeof(pack_info))) > 0)
    {
      p = (char *)&pack_info;
      for (index = 0; index < 14; index++)
      {
        printf("%d", p[index]);
      }
      printf("jiangyibo recvs %d\n", pack_info.id);
      if (pack_info.id == 3)
      {
        if (pReal->tr069state == 4)
        {
          exeShell("/etc/init.d/freecwmpd start&");
        }
      }
      else if (pack_info.id == 4)
      {
        if (pReal->tr069state == 3)
        {
          exeShell("/etc/init.d/freecwmpd stop&");
        }
      }
      else if (pack_info.id == 5)
      {
        if (pReal->tr069state == 3)
        {
          exeShell("/etc/init.d/freecwmpd stop&");
        }
      }
      else if (pack_info.id == 6)
      {
        if (pack_info.data[0] == 3)
        {
          system("reboot -f");
        }
      }
      else if (pack_info.id == 7)
      {
        if (pack_info.data[0] == 3)
        {
          system("uci set pifii.register.udpport=1&&uci commit pifii");
        }
      }
      else if (pack_info.id == 8)
      {
        if (pack_info.data[0] == 3)
        {
          system("/usr/sbin/updateUdpReport.sh &");
        }
      }
    }
    else
    {

      break;
    }
  }
  printf("cucuo \n");

  close(client_socket_fd);
  goto start;
  return 0;
}
