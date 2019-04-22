/*{
    "window.zoomLevel": 0,
    "files.autoSave": "off"
} > 
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
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/wait.h>

#include <sys/ioctl.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <pthread.h>
#include "b64.h"
#include "uci.h"
#include "json.h"
#include "httppost.h"

#define ROUTER_PORT 8880
#define HOMEDEV_PORT 8880

#define BUFFER_SIZE 1200
#define FILE_NAME_MAX_SIZE 512

#define MAX_TEXT 512

#define MAXBUF 1500
#define DEV_SIZE 6
#define APP_VERSION 1
#define SERVER_IP "192.168.3.68" //tz.pifii.com
#define SERVER_PORT "8880"
#define HTTPPOST_IP "192.168.3.68" //tz.pifii.com
#define HTTPPOST_PORT "8082"
#define HTTPPOST_PATH "/wifi_home_gx/acsjson"
#define HARD_VERSION "v2.1.8"
#define SOFT_VERSION "v2.1.29"
#define DEVICE_TYPE_E "IJLY_410"
//#define SOFT_VERSION_SHELL "cat /etc/sysinfo.conf |grep soft_version|cut -c 14-"
#define SOFT_VERSION_SHELL "cat /etc/openwrt_version"

int debug_mode = 0;

static char *fc_script = "/usr/sbin/freecwmp";
static char *fc_script_set_actions = "/tmp/freecwmp_set_action_values.sh";
#define HOMEPWD "/etc/config/"
#define JSPWD "/usr/lib/js/"
//#define JSPWD "./js/"
#define ErrorJson "{\"name\": \"errorResponse\",\"version\": \"1.0.0\",\"serialnumber\": \"112233445566\",\"error\": \"1\"}"
#define FileJson "{\"name\": \"getResponse\",\"version\": \"1.0.0\",\"serialnumber\": \"%s\",\
				\"keyname\": \"file\",\"packet\": {\"path\": \"/etc/config/\",\"filename\": \"%s\",\"data\": \"%s\"}}"
#define ConfigJson "{\"name\": \"getResponse\",\"version\": \"1.0.0\",\"serialnumber\": \"%s\",\
				\"keyname\": \"config\",\"packet\": {\"data\": \"%s\"}}"
#define CommandJson "{\"name\": \"getResponse\",\"version\": \"1.0.0\",\"serialnumber\": \"%s\",\
				\"keyname\": \"command\",\"packet\": {\"data\": \"%s\"}}"
#define SetResponse "{\"name\": \"setResponse\",\"version\": \"1.0.0\",\"serialnumber\": \"%s\",\"keyname\": \"%s\",\
					\"packet\": {\"data\": \"%s\"}}"
#define DownloadResponse "{\"name\": \"setResponse\",\"version\": \"1.0.0\",\"serialnumber\": \"%s\",\"keyname\": \"%s\",\
					\"packet\": {\"data\": \"%s\",\"ProductClass\":\"%s\",\"Manufacturer\":\"%s\",\"Status\":\"%s\"}}"
#define GetResponse "{\"name\": \"getResponse\",\"version\": \"1.0.0\",\"serialnumber\": \"%s\",\
				\"keyname\": \"config\",\"packet\": {%s}}"
#define GetReport "{\"name\": \"getResponse\",\"version\": \"1.0.0\",\"serialnumber\": \"%s\",\
				\"keyname\": \"reportconfig\",\"packet\": {%s}}"
#define GetBlackmac "{\"name\": \"getResponse\",\"version\": \"1.0.0\",\"serialnumber\": \"%s\",\
				\"keyname\": \"blackmac\",\"packet\": {%s}}"
#define TestJson "{\"name\": \"get\",\"version\": \"1.0.0\",\"serialnumber\": \"112233445566\",\
				\"keyname\": \"getvalue\",\"packet\": {\"UpTime\": \"sss\",\"wan_type\": \"sss\"}}"
#define HomeResponse "{\"sid\": \"%s\",\"id\": \"%s\",\"ver\": \"%s\",\
				\"cmdtype\": \"2\",\"result\":\"ok\", \"errordes\":\"\",\"date\":\"2017-01-01\",\"time\":\"01-02-03\",\"week\":\"2\"}"
#define HomeRespApp "{\"Factory\": \"pifii_smart_ok\"}"
#define HomeSwitchOn "{\"sid\": \"1\",\"id\": \"%s\",\"ver\": \"%s\",\
				\"cmdtype\": \"4099\",\"subcmd\": 1,\"value\": 0}"
#define HomeSwitchOff "{\"sid\": \"1\",\"id\": \"%s\",\"ver\": \"%s\",\
				\"cmdtype\": \"4099\",\"subcmd\": 1,\"value\": 1}"
#define HomeDeviceState "{\"name\": \"update_smartdevs\", \"ProductClass\": \"%s\",\"serialnumber\": \"%s\", \"devs\":[%s]}"
#define HomeDeviceInit "{\"name\": \"msg\",\"version\": \"1.0.0\",\"packet\": [{\"mainid\": \"%s\",\"list\":[%s]}],\"serialnumber\": \"%s\",\"keyname\": \"newSecurity\"}"
#define SafeDevTrap "{\"keyname\": \"smartSecurityMsg\",	\"name\": \"msg\",\"packet\": [{\"sid\": \"1\",	\"mainid\": \"%02X%02X\",\"ver\": \"16\",\
		\"devtype\": \"%c\",\"devid\": \"%02X%02X\",\"state\": \"%02X\"}],\"serialnumber\": \"%s\",\"version\": \"1.0.0\"}"
#define SDevReport "{\"id\": \"%s\",\"devtype\": \"3\",\"cmdtype\": \"%s\",\"list\": [%s]}"

       
char informRes[1500];
pthread_mutex_t mutex;
char reportServerIp[32];
char reportServerPort[32];

char httpPostServerIp[32];
char httpPostServerPort[32];
char httpPostServerPath[32];
char deviceType[32];
char deviceVer[32];

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

typedef struct dataType{
    int  enable;
    char id[8];
    char cmd[8];
    char type;
}DataType;



typedef struct Node  
{//结构实现  
    DataType data;  
    struct Node* next;     
}Node, *PNode; 

typedef struct smartDev{
    char name[10];
    unsigned  char state;
    Node *dev;
}SmartDev;


char *GetArrayByKeyString(json_object *jobj,int index, const char *sname)
{
  json_object *pval = NULL;
  json_object *tpval = NULL;
  enum json_type type;
  tpval = json_object_array_get_idx(jobj,index);
  if(tpval == NULL)
  {
    return  NULL;
  }
  pval = json_object_object_get(tpval, sname);
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

json_object *GetArrayByKeyObject(json_object *jobj,int index, const char *sname)
{
  json_object *pval = NULL;
  json_object *tpval = NULL;
  enum json_type type;
  tpval = json_object_array_get_idx(jobj,index);
  if(tpval == NULL)
  {
    return  NULL;
  }
  pval = json_object_object_get(tpval, sname);
  if (NULL != pval)
  {
    type = json_object_get_type(pval);
    switch (type)
    {
     case json_type_array:
      return pval;

    default:
      return NULL;
    }
  }
  return NULL;
} 

void InitList(PNode* PHead)//初始化  
{  

    *PHead = NULL;  
}  
  
PNode ByeNode(DataType data)//申请一个结点  
{  
    PNode newNode = NULL;  
    newNode = (PNode)malloc(sizeof(Node));  
    if (NULL == newNode)  
    {  
        printf("out of memory.\n");  
        exit(1);  
    }  
    else  
    {  
        newNode->data = data;  
        newNode->next = NULL;  
    }  
    return newNode;  
}  
void PopBack(PNode* PHead)//尾删  
{  

    if (NULL == *PHead)  
    {  
        return;  
    }  
    else if(NULL == (*PHead)->next)  
    {  
        PNode TempNode = *PHead;  
        free(TempNode);  
        TempNode = NULL;  
        *PHead = NULL;  
    }  
    else  
    {  
        PNode PCur = *PHead;  
        while (PCur->next->next)  
        {  
            PCur = PCur->next;  
        }  
        PCur->next = NULL;  
    }  
}  
  
void PushBack(PNode* PHead, DataType data)//尾插  
{  

    if (NULL == *PHead)  
    {  
        *PHead = ByeNode(data);  
    }  
    else  
    {  
        PNode PCur = NULL;  
        PCur = *PHead;  
        while (PCur->next)  
        {  
            PCur = PCur->next;  
        }  
        PCur->next = ByeNode(data);  
    }  
}  
 
void Destroy(PNode* PHead)//销毁  
{  

    PNode PCur = *PHead;  
    while (PCur->next)  
    {  
        PNode Dnode = PCur;  
        PCur = PCur->next;  
        free(Dnode);  
        Dnode = NULL;  
    }  
}  
  
int Empty(PNode PHead)//判空  
{  
    if (NULL == PHead)  
        return 0;  
    else  
        return 1;  
}  
  
int Size(PNode PHead)//求链表中结点的个数  
{   
    PNode Node = PHead;  
    int num = 0;  
    while (Node)  
    {  
        num++;  
        Node = Node->next;  
    }  
    return num;  
}  
  
void PrintList(PNode* PHead)//打印单链表  
{  
    PNode PCur = *PHead;  
    while (PCur)  
    {  
        printf("%d->",PCur->data);  
        PCur = PCur->next;  
    }  
    printf("NULL\n");  
}  
  
void Insert(PNode pos, DataType data)//在data后插入结点  
{  
    PNode newNode = ByeNode(data);  
    PNode PreNode = pos;  
    newNode->next = PreNode->next;  
    PreNode->next = newNode;  
}  

SmartDev *startDev;

int initSmartDevArray()
{
  startDev= NULL;
}

int procSmartDevArray(json_object *jobj)
{
  
    Node *start;
    
    json_object *pval = NULL;
    json_object *tpval = NULL;
    DataType data;
    int length ;
    int tlength ;
    int index;
    char *mainid,*id,*type;
    memset(&data,0,sizeof(DataType));
    if(jobj == NULL)
    {
      return 0;
    }    
    if(startDev == NULL)
    {
      startDev = (SmartDev *)malloc(sizeof(SmartDev));
      startDev->dev = NULL;
    }

    start = startDev->dev;
    if(start != NULL)
    {
        Destroy(&start);
        InitList(&start);
    }
    length =  json_object_array_length(jobj);
    if(length>0)
    {
        mainid =  GetArrayByKeyString(jobj,0,"mainid");
        printf("jiangyibo mainid = %s\n",mainid);
        strcpy(startDev->name,mainid);
        pval = GetArrayByKeyObject(jobj,0,"list");
        if(pval!=NULL)
        {
             
            tlength =  json_object_array_length(pval);
            printf("jiangyibo tlength = %d\n",tlength);
            for(index = 0;index <tlength ;index ++)
            {
                id   =  GetArrayByKeyString(pval,index,"id");
                type =  GetArrayByKeyString(pval,index,"type");
                printf("jiangyibo mainid2 = %s\n",id);
                strcpy(data.id,id);
                strcpy(data.cmd,"00");
                data.type = *type;
                if(start== NULL)
                {
                   
                   startDev->dev = ByeNode(data);
                   start = startDev->dev;
                   printf("jiangyibo type = %s\n",type);
                }else {
                  printf("jiangyibo type2 = %s\n",type);
                   PushBack(&start,data);
                }
            }
        }
    }
    return 1;
    
}

int sendCheckSmartDev(char *anfangid,char *sendmsgData)
{
    char buf[128];
    char mainid[10];
    DataType data;
     int index = 0;

    int rsize = 0;
    Node *PCur=NULL;

    memset(buf,0,128);
    
    sprintf(sendmsgData, HomeDeviceInit, anfangid ,"",deviceMac);
    if(startDev == NULL)
    {
      
      return 1;
    }
    if(startDev->dev == NULL )
    {
        
        return 0;
    }else{
        PCur = startDev->dev;
        while(PCur)
        {
          if(PCur->data.enable == 1)
          {
            sprintf(buf,"{\"id\":\"%s\",\"type\":\"%c\",\"new\":\"1\"}",PCur->data.id,PCur->data.type);
            sprintf(sendmsgData, HomeDeviceInit, anfangid ,buf,deviceMac);
            PCur->data.enable = 0;
            return 1;
          }
          PCur=PCur->next;
        }
    }
    return 0;
}

int setZeroSmartDev()
{

    char mainid[10];
    DataType data;
     int index = 0;

    int rsize = 0;
    Node *PCur=NULL;


    if(startDev == NULL)
    {
      return 1;
    }
    if(startDev->dev == NULL )
    {
        return 0;
    }else{
        PCur = startDev->dev;
        while(PCur)
        {
          strcpy(PCur->data.cmd,"00");
          PCur=PCur->next;
        }
    }
    return 0;
}

char smartDevToCenter(char *data,char *sdata)
{

     unsigned char value = (0xff&data[5]);
     memcpy(sdata,data+1,4);
     printf("jiangyibo return send %02x\n",value);
     if(value == 0x03)
     {
       sprintf(sdata+4,"02X",value);
       return '1';
     }
     else if(value == 0xC0)
     {
       strcpy(sdata,"+CMD=C0\r\n");
       return '2';
     }  
     else if(value == 0x0C)
     {
       strcpy(sdata,"+CMD=0C\r\n");
       return '2';
     }            
     else if(value == 0x30)
     {
       strcpy(sdata,"+CMD=30\r\n");
       return '2';
     }     
     else if(value == 0x50)
     {
       strcpy(sdata,"+CMD=30\r\n");
       return '2';
     }
     else if(value == 0x5C)
     {
       strcpy(sdata,"+CMD=30\r\n");
       return '3';
     }
     else if(value == 0x34)
     {
       strcpy(sdata,"+CMD=30\r\n");
       return '4';
     }
     else if(value == 0xFC)
     {
       strcpy(sdata,"+CMD=30\r\n");
       return '5';
     }     
     else if(value == 0x74)
     {
       strcpy(sdata,"+CMD=30\r\n");
       return '6';
     }  
     else 
     {
        value = value&0x0f;
        if(value == 0x0D||value == 0x0E||value == 0x0F)
        {
          strcpy(sdata,"+CMD=30\r\n");
          return '7';
        } else{
            return '8';
        }
     }
}

char smartDevType(char *type)
{
    unsigned char value = (0xff&type[0]);
     printf("jiangyibo ooooo %02x\n",value);
     if(value == 0xC0||value == 0x0c||value == 0x03||value == 0x30)
     {
       return '1';
     }
     else if(value == 0x50)
     {
       return '2';
     }
     else if(value == 0x5C)
     {
       return '3';
     }
     else if(value == 0x34)
     {
       return '4';
     }
     else if(value == 0xFC)
     {
       return '5';
     }     
     else if(value == 0x74)
     {
       return '6';
     }  
     else if(value == 0x0)
     {
       return '9';
     }       
     else 
     {
        value = value&0x0f;
        if(value == 0x0D||value == 0x0E||value == 0x0F)
        {
          return '7';
        } else{
            return '8';
        }
     }
}

int findSmartDevArray(char *mid,char *id,char *type)
{
    char buf[256];
    char mainid[10];
    DataType data;
    memset(buf,0,256);
    int index = 0;
    int state = 0;

    int rsize = 0;
    Node *PCur=NULL;
    sprintf(mainid,"%02X%02X",0xff&mid[0],0xff&mid[1]);
    sprintf(data.id,"%02X%02X",0xff&id[0],0xff&id[1]);
    sprintf(data.cmd,"%02X",0xff&type[0]);
    data.type = smartDevType(type);
    if(data.type == '9')
    {
      return 0;
    }
    if(startDev == NULL)
    {
      return 0;
    }
    if(strcmp(startDev->name,mainid))
    {
       return 0;
    }
    printf("jiangyibo cefang %02x\n",startDev->state&0xff);



    if((startDev->state&0xff) != 0xC0)
    {
      printf("jiangyibo cefang %02x\n",startDev->state&0xff);
          if(startDev->dev == NULL )
          {
              return 0;
          }else{
              PCur = startDev->dev;
              while(PCur)
              {
                if(!strcmp(PCur->data.id,data.id))
                {
                  strcpy(PCur->data.cmd,data.cmd);
                  PCur->data.type = data.type;
                  // in device list change state
                  if((0xff&type[0])== 0x0C)
                  {
                    startDev->state = 0x0C;
                    setZeroSmartDev();
                    state = 0;
                    return 1;
                  }else if((0xff&type[0])== 0xC0){
                    startDev->state = 0xC0;
                    state = 1;
                    return 1;
                  }else{
                    return 0;
                  }
                }
                PCur=PCur->next;
              }
              return 0;
          }
    }else {
         if(startDev->dev == NULL )
          {
             return 0;

          }else{
              PCur = startDev->dev;
              while(PCur)
              {
                if(!strcmp(PCur->data.id,data.id))
                {
                  strcpy(PCur->data.cmd,data.cmd);
                  PCur->data.type = data.type;
                  if((0xff&type[0])== 0x0C)
                  {
                    startDev->state = 0x0C;
                    setZeroSmartDev();
                    state = 0;
                    return 1;
                  }else if((0xff&type[0])== 0xC0){
                    startDev->state = 0xC0;
                    state = 1;
                    return 1;
                  }else{
                    return 1;
                  }                  
                }
                PCur=PCur->next;
              }
              return 0;
          }
    }

}

int findSmartDevArrayAdd(char *mid,char *id,char *type)
{
    char buf[256];
    char mainid[10];
    DataType data;
    memset(buf,0,256);
    int index = 0;
    int state = 0;

    int rsize = 0;
    Node *PCur=NULL;
    sprintf(mainid,"%02X%02X",0xff&mid[0],0xff&mid[1]);
    sprintf(data.id,"%02X%02X",0xff&id[0],0xff&id[1]);
    sprintf(data.cmd,"%02X",0xff&type[0]);
    data.type = smartDevType(type);
    if(startDev == NULL)
    {
      return 0;
    }
    if(strcmp(startDev->name,mainid))
    {
       return 0;
    }
    printf("jiangyibo cefang %02x\n",startDev->state&0xff);

    if((0xff&type[0])== 0x0C)
    {
       startDev->state = 0x0C;
       state = 1;
    }else if((0xff&type[0])== 0xC0){
       startDev->state = 0xC0;
       state = 1;
    }

    if((startDev->state&0xff) == 0x0C&&state == 0)
    {
      printf("jiangyibo cefang %02x\n",startDev->state&0xff);
          if(startDev->dev == NULL )
          {
             
              startDev->dev = ByeNode(data);
              return 0;
          }else{
              PCur = startDev->dev;
              while(PCur)
              {
                if(!strcmp(PCur->data.id,data.id))
                {
                  strcpy(PCur->data.cmd,data.cmd);
                  PCur->data.type = data.type;
                  return 0;
                }
                PCur=PCur->next;
              }
              data.enable = 1;
              PCur = startDev->dev;
              PushBack(&PCur,data);
              return 0;
          }
    }else {
         if(startDev->dev == NULL )
          {
              
              startDev->dev = ByeNode(data);
              return 1;

          }else{
              PCur = startDev->dev;
              while(PCur)
              {
                if(!strcmp(PCur->data.id,data.id))
                {
                  strcpy(PCur->data.cmd,data.cmd);
                  PCur->data.type = data.type;
                  return 1;
                }
                PCur=PCur->next;
              }
              data.enable = 1;
              PCur = startDev->dev;
              PushBack(&PCur,data);
              return 1;
          }
    }

}

int postSmartDevArray(char *postBuf)
{
    char buf[1400];
    memset(buf,0,1400);
    int index = 0;

    int rsize = 0;
    Node *PCur=NULL;

    if(startDev == NULL)
    {
      return 0;
    }
    rsize = Size(startDev->dev);
    if(startDev->dev != NULL )
    {
        if( rsize > 1 )
        {
            PCur = startDev->dev;  
            snprintf(buf, 1400, "{\"id\":\"%s\",\"remark_id\":\"%c%s\",\"state\":\"%s\",\"new\":\"1\"}", PCur->data.id,PCur->data.type,PCur->data.id,PCur->data.cmd);
            PCur = PCur->next;
            while(PCur)
            {  
                snprintf(buf, 1400, "%s,{\"id\":\"%s\",\"remark_id\":\"%c%s\",\"state\":\"%s\",\"new\":\"1\"}", buf, PCur->data.id,PCur->data.type,PCur->data.id,PCur->data.cmd);
                PCur = PCur->next;  
            }  
        }
        else
        {
                PCur = startDev->dev;  
                snprintf(buf, 1400, "{\"id\":\"%s\",\"remark_id\":\"%c%s\",\"state\":\"%s\",\"new\":\"1\"}",PCur->data.id,PCur->data.type,PCur->data.id,PCur->data.cmd);
        }
    }

    if(0xff&startDev->state == 0xC0)
    {
      snprintf(postBuf, 1400, SDevReport,startDev->name,"5004",buf );
    }else {
      snprintf(postBuf, 1400, SDevReport,startDev->name,"5005",buf );
    }
//    printf("jiangyibo dingshifa %s\n",postBuf);
    return 1;
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

int external_get_action(char *action, char *name, char **value)
{
  //lfc_log_message(NAME, L_NOTICE, "executing get %s '%s'\n",
  //		action, name);
  int pid;
  int pfds[2];
  char *c = NULL;

  if (debug_mode > 0)
    printf("tz action %s %s\n", action, name);

  if (pipe(pfds) < 0)
    return -1;

  if ((pid = fork()) == -1)
    goto error;

  if (pid == 0)
  {
    /* child */
    const char *argv[8];
    int i = 0;
    argv[i++] = "/bin/sh";
    argv[i++] = fc_script;
    argv[i++] = "--newline";
    argv[i++] = "--value";
    argv[i++] = "get";
    argv[i++] = action;
    argv[i++] = name;
    argv[i++] = NULL;

    close(pfds[0]);
    dup2(pfds[1], 1);
    close(pfds[1]);
    execvp(argv[0], (char **)argv);
    exit(ESRCH);
  }
  else if (pid < 0)
    goto error;

  /* parent */
  close(pfds[1]);

  int status;
  while (wait(&status) != pid)
  {
    printf("waiting for child to exit");
  }

  char buffer[256];
  ssize_t rxed;
  int t;

  *value = NULL;
  while ((rxed = read(pfds[0], buffer, sizeof(buffer))) > 0)
  {

    if (*value)
    {
      t = asprintf(&c, "%s%.*s", *value, (int)rxed, buffer);
      if (debug_mode > 0)
        printf("tz get kkkkk%s\n", c);
    }
    else
    {

      t = asprintf(&c, "%.*s", (int)rxed, buffer);
      /*      *value = NULL;
      goto done;
*/
      if (debug_mode > 0)
        printf("tz get %s\n", c);
    }
    if (debug_mode > 0)
      printf("tz get kkkkk sss %d %s\n", t, c);
    if (t == -1)
      goto error;

    free(*value);
    *value = strdup(c);
    free(c);
  }

  if (!(*value))
  {
    goto done;
  }

  if (!strlen(*value))
  {
    FREE(*value);
    goto done;
  }

  if (rxed < 0)
    goto error;

done:
  close(pfds[0]);
  return 0;

error:
  free(c);
  FREE(*value);
  close(pfds[0]);
  return -1;
}

int external_set_action_write(char *action, char *name, char *value)
{

  FILE *fp;

  if (access(fc_script_set_actions, R_OK | W_OK | X_OK) != -1)
  {
    fp = fopen(fc_script_set_actions, "a");
    if (!fp)
      return -1;
  }
  else
  {
    fp = fopen(fc_script_set_actions, "w");
    if (!fp)
      return -1;

    fprintf(fp, "#!/bin/sh\n");

    if (chmod(fc_script_set_actions,
              strtol("0700", 0, 8)) < 0)
    {
      return -1;
    }
  }

  fprintf(fp, "/bin/sh %s set %s %s '%s'\n", fc_script, action, name, value);

  fclose(fp);

  return 0;
}

int external_set_action_execute()
{
  int pid = 0;
  if ((pid = fork()) == -1)
  {
    return -1;
  }

  if (pid == 0)
  {
    /* child */

    const char *argv[3];
    int i = 0;
    argv[i++] = "/bin/sh";
    argv[i++] = fc_script_set_actions;
    argv[i++] = NULL;

    execvp(argv[0], (char **)argv);
    exit(ESRCH);
  }
  else if (pid < 0)
    return -1;

  /* parent */
  int status;
  while (wait(&status) != pid)
  {
    printf("waiting for child to exit");
  }

  // TODO: add some kind of checks
  /*
	if (remove(fc_script_set_actions) != 0)
		return -1;
*/
  return 0;
}

int external_download(char *url, char *size)
{
  int pid = 0;

  if ((pid = fork()) == -1)
    return -1;

  if (pid == 0)
  {
    /* child */

    const char *argv[8];
    int i = 0;
    argv[i++] = "/bin/sh";
    argv[i++] = fc_script;
    argv[i++] = "download";
    argv[i++] = "--url";
    argv[i++] = url;
    argv[i++] = "--size";
    argv[i++] = size;
    argv[i++] = NULL;

    execvp(argv[0], (char **)argv);
    exit(ESRCH);
  }
  else if (pid < 0)
    return -1;

  /* parent */
  int status;
  while (wait(&status) != pid)
  {
    printf("waiting for child to exit");
  }

  if (WIFEXITED(status) && !WEXITSTATUS(status))
    return 0;
  else
    return 1;

  return 0;
}

int commandDownload(char *url, char *size)
{
  external_download(url, size);
  return 1;
}

typedef struct homedevice
{
  unsigned int addr;
  int uptime;
  int enable;
  char mac[18];
  char devtype[8];
  char ver[16];  
  char statstr[64];
} HomeDevice;

HomeDevice homeDev[20];

int initHomeDevice()
{
  memset(homeDev, 0, 20 * sizeof(HomeDevice));
  return 1;
}

int AddHomeDeviceShort(char *mac, unsigned int addr,int port, char *devtype,char *ver, char *statstr)
{
  int i = 0;
  time_t uptime;
  uptime = time(NULL);

  pthread_mutex_lock(&mutex); //锁定互斥锁
  for (i = 0; i < 20; i++)
  {

    if (homeDev[i].enable == 0)
    {

      strcpy(homeDev[i].mac, mac);
      homeDev[i].addr = addr;
      if (devtype != NULL)
      {
        strcpy(homeDev[i].devtype, devtype);
      }
      if (statstr != NULL)
      {
        strcpy(homeDev[i].statstr, statstr);
      }
      if (ver != NULL)
      {
        strcpy(homeDev[i].ver, ver);
      }
      homeDev[i].uptime = port;
      homeDev[i].enable = 1;

      pthread_mutex_unlock(&mutex); //打开互斥锁
      return 1;
    }
    else if (!strcmp(mac, homeDev[i].mac))
    {
      if (homeDev[i].addr == addr)
      {
        homeDev[i].uptime = port;
      }
      else
      {
        homeDev[i].addr = addr;
        homeDev[i].uptime = port;
      }

      if (devtype != NULL)
      {
        strcpy(homeDev[i].devtype, devtype);
      }
      if (statstr != NULL)
      {
        strcpy(homeDev[i].statstr, statstr);
      }

      pthread_mutex_unlock(&mutex); //打开互斥锁
      return 1;
    }
  }
  pthread_mutex_unlock(&mutex); //打开互斥锁
  return 0;
}

int AddHomeDevice(char *mac, unsigned int addr, char *devtype,char *ver, char *statstr)
{
  int i = 0;
  time_t uptime;
  uptime = time(NULL);

  pthread_mutex_lock(&mutex); //锁定互斥锁
  for (i = 0; i < 20; i++)
  {

    if (homeDev[i].enable == 0)
    {

      memcpy(homeDev[i].mac, mac, 17);
      homeDev[i].addr = addr;
      if (devtype != NULL)
      {
        strcpy(homeDev[i].devtype, devtype);
      }
      if (statstr != NULL)
      {
        strcpy(homeDev[i].statstr, statstr);
      }
      if (ver != NULL)
      {
        strcpy(homeDev[i].ver, ver);
      }
      homeDev[i].uptime = uptime;
      homeDev[i].enable = 1;

      pthread_mutex_unlock(&mutex); //打开互斥锁
      return 1;
    }
    else if (!strcmp(mac, homeDev[i].mac))
    {
      if (homeDev[i].addr == addr)
      {
        homeDev[i].uptime = uptime;
      }
      else
      {
        homeDev[i].addr = addr;
        homeDev[i].uptime = uptime;
      }

      if (devtype != NULL)
      {
        strcpy(homeDev[i].devtype, devtype);
      }
      if (statstr != NULL)
      {
        strcpy(homeDev[i].statstr, statstr);
      }

      pthread_mutex_unlock(&mutex); //打开互斥锁
      return 1;
    }
  }
  pthread_mutex_unlock(&mutex); //打开互斥锁
  return 0;
}


int GetHomeDevice(char *value)
{
  int i;
  int index = 0;
  time_t lt;
  lt = time(NULL);
  char tempstr[1400];
  int rc;
  
  pthread_mutex_lock(&mutex); //锁定互斥锁
  for (i = 0; i < 20; i++)
  {
    if (homeDev[i].enable == 1)
    {
      if (lt - homeDev[i].uptime > 120)
      {
        homeDev[i].enable = 0;
      }
      else
      {
        memset(tempstr, 0, 1400);
        if (index++ == 0)
        {
          sprintf(tempstr, "{\"id\":\"%s\",\"devtype\":\"%s\",\"ver\":\"%s\",\"statstr\":\"%s\"}", homeDev[i].mac, homeDev[i].devtype,homeDev[i].ver, homeDev[i].statstr);
        }
        else
        {
          sprintf(tempstr, ",{\"id\":\"%s\",\"devtype\":\"%s\",\"ver\":\"%s\",\"statstr\":\"%s\"}", homeDev[i].mac, homeDev[i].devtype, homeDev[i].ver,homeDev[i].statstr);
        }
        strcat(value, tempstr);
      }
    }
  }
  memset(tempstr, 0, 1400);
  rc = postSmartDevArray(tempstr);
  if(rc != 0)
  {
      if(index == 0)
      {
        
      }
      else
      {
        sprintf(tempstr, ",%s",tempstr);
      }
      strcat(value, tempstr);
  }
  pthread_mutex_unlock(&mutex); //打开互斥锁
  return 0;
}

int FindHomeDevice(char *mac)
{
  int i;
  for (i = 0; i < 20; i++)
  {
    if (homeDev[i].enable == 1)
    {
      if (!strcmp(mac, homeDev[i].mac))
      {
        return homeDev[i].addr;
      }
    }
  }
  return 0;
}

int FindHomeDevicePort(char *mac,int *port)
{
  int i;
  for (i = 0; i < 20; i++)
  {
    if (homeDev[i].enable == 1)
    {
      if (!strcmp(mac, homeDev[i].mac))
      {
        *port = homeDev[i].uptime;
        return homeDev[i].addr;
      }
    }
  }
  return 0;
}

int commandSendtoHomeDevicePort(int server_socket_fd, char *mac, char *sendData)
{
  int port;
  int addr = FindHomeDevicePort(mac,&port);
  struct sockaddr_in client_addr;
  socklen_t client_addr_length = sizeof(client_addr);

  printf("send homesmart command 111 %0x\n", addr);

  if (addr == 0)
  {
    return 0;
  }
  else
  {
    bzero(&client_addr, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(0xffff&port);
    client_addr.sin_addr.s_addr = addr;
    if (debug_mode > 0)
      printf("command send %s port = %d\n", sendData,0xffff&port);
    if (sendto(server_socket_fd, sendData, strlen(sendData), 0, (struct sockaddr *)&client_addr, client_addr_length) < 0)
    {
      if (debug_mode > 0)
        printf("Send File Name Failed:");
    }
    else
    {
      if (debug_mode > 0)
        printf("Send ok\n");
    }

    return 1;
  }
}

int commandSendtoHomeDevice(int server_socket_fd, char *mac, char *sendData)
{
  int addr = FindHomeDevice(mac);
  struct sockaddr_in client_addr;
  socklen_t client_addr_length = sizeof(client_addr);

  printf("send homesmart command 111 %0x\n", addr);

  if (addr == 0)
  {
    return 0;
  }
  else
  {
    bzero(&client_addr, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(HOMEDEV_PORT);
    client_addr.sin_addr.s_addr = addr;
    if (debug_mode > 0)
      printf("command send %s\n", sendData);
    if (sendto(server_socket_fd, sendData, strlen(sendData), 0, (struct sockaddr *)&client_addr, client_addr_length) < 0)
    {
      if (debug_mode > 0)
        printf("Send File Name Failed:");
    }
    else
    {
      if (debug_mode > 0)
        printf("Send ok\n");
    }

    return 1;
  }
}

int commandFactoryset()
{
  system("rm -rf /overlay/*");
  system("reboot");
  return 1;
}

int setShellValue(char *value)
{

  char *c = NULL;
  if (NULL == value || '\0' == value[0])
  {
    if (external_get_action("value", "text", &c))
      goto error;
  }
  else
  {
    c = strdup(value);
  }
  if (c)
  {

    FREE(c);
  }
  return 0;
error:
  return -1;
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

boolean GetBoolByEtype(json_object *jobj, const char *sname)
{
  json_object *pval = NULL;
  enum json_type type;
  pval = json_object_object_get(jobj, sname);
  if (NULL != pval)
  {
    type = json_object_get_type(pval);
    switch (type)
    {
    case json_type_boolean:
      return json_object_get_boolean(pval);

    default:
      return 0;
    }
  }
  return 0;
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
int getConfigFile(char *msg, char *filename)
{
  char temp[64];
  sprintf(temp, "%s%s", HOMEPWD, filename);
  FILE *pFile = fopen(temp, "r"); //

  if (pFile == NULL)
  {
    return 0;
  }

  fseek(pFile, 0, SEEK_END); //把指针移动到文件的结尾 ，获取文件长度
  int len = ftell(pFile);    //获取文件长度

  rewind(pFile);             //把指针移动到文件开头 因为我们一开始把指针移动到结尾，如果不移动回来 会出错
  fread(msg, 1, len, pFile); //读文件
  msg[len] = 0;              //把读到的文件最后一位 写为0 要不然系统会一直寻找到0后才结束

  fclose(pFile); // 关闭文件
  return len;
}

void getFileData(char *msg, char *filename)
{
  char temp[64];
  sprintf(temp, "%s%s", JSPWD, filename);
  FILE *pFile = fopen(temp, "r"); //获取文件的指针

  fseek(pFile, 0, SEEK_END); //把指针移动到文件的结尾 ，获取文件长度
  int len = ftell(pFile);    //获取文件长度

  rewind(pFile);             //把指针移动到文件开头 因为我们一开始把指针移动到结尾，如果不移动回来 会出错
  fread(msg, 1, len, pFile); //读文件
  msg[len] = 0;              //把读到的文件最后一位 写为0 要不然系统会一直寻找到0后才结束

  fclose(pFile); // 关闭文件
}

int jsonGetConfig(SOCKET s, json_object *config)
{
  int rc = 0;
  char tempstr[2048];
  char sendbuf[2048];
  char kvbuf[2048];
  char *tempVal = NULL;
  enum json_type type;
  int index = 0;
  json_object *obj = config;
  char *key;
  struct json_object *val;
  char *value;
  memset(kvbuf, 0, 2048);

  if (config == NULL)
  {
    if (debug_mode > 0)
      printf("jyb test error\n");
    return;
  }

  struct lh_entry *entry = json_object_get_object(obj)->head;
  for (; entry != NULL;)
  {
    if (debug_mode > 0)
      printf("ri mabi\n");
    if (entry)
    {
      key = (char *)entry->k;
      val = (struct json_object *)entry->v;
      entry = entry->next;
    }
    else
    {
      if (debug_mode > 0)
        printf("mabi\n");
      break;
    }
    if (debug_mode > 0)
      printf("tz sfdsfsa mabi\n");
    type = json_object_get_type(val);
    switch (type)
    {
    case json_type_string:
      tempVal = json_object_get_string(val);
      break;
    default:
      break;
    }
    if (debug_mode > 0)
      printf("jyb test %s %s\n", key, tempVal);
    memset(tempstr, 0, 1024);
    sprintf(tempstr, "%s", key);
    value = NULL;
    if (external_get_action("value", tempstr, &value) == 0)
    {
      if (index++ == 0)
      {
        if (value == NULL)
        {
          if (strcmp(key, "InternetGatewayDevice.DeviceInfo.black_url") == 0)
          {
            snprintf(kvbuf, 1792, "\"%s\":[]", key);
          }
          else  if (strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_value") == 0)
          {
            snprintf(kvbuf, 1792, "\"%s\":\"\"", key);
          }
          else  if (strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_value_5G") == 0)
          {
            snprintf(kvbuf, 1792, "\"%s\":\"\"", key);
          }          
          else
          {
            snprintf(kvbuf, 1792, "\"%s\":\"\"", key);
          }
        }
        else
        {
          if (strcmp(key, "InternetGatewayDevice.DeviceInfo.black_url") == 0)
          {
            snprintf(kvbuf, 1792, "\"%s\":%s", key, value);
          }
          else   if (strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_value") == 0)
          {
            snprintf(kvbuf, 1792, "\"%s\":%s", key, value);
          }
          else   if (strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_value_5G") == 0)
          {
            snprintf(kvbuf, 1792, "\"%s\":%s", key, value);
          }          
          else
          {
            snprintf(kvbuf, 1792, "\"%s\":\"%s\"", key, value);
          }
        }
      }
      else
      {
        if (value == NULL)
        {
          if (strcmp(key, "InternetGatewayDevice.DeviceInfo.black_url") == 0)
          {
            snprintf(kvbuf, 1792, "%s,%s:[]", kvbuf, key);
          }
          else          if (strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_value") == 0)
          {
            snprintf(kvbuf, 1792, "%s,%s:\"\"", kvbuf, key);
          }
          else          if (strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_value_5G") == 0)
          {
            snprintf(kvbuf, 1792, "%s,%s:\"\"", kvbuf, key);
          }          
          else
          {
            snprintf(kvbuf, 1792, "%s,\"%s\":\"\"", kvbuf, key);
          }
        }
        else
        {
          if (strcmp(key, "InternetGatewayDevice.DeviceInfo.black_url") == 0)
          {
            snprintf(kvbuf, 1792, "%s,\"%s\":%s", kvbuf, key, value);
          }
          else           if (strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_value") == 0)
          {
            snprintf(kvbuf, 1792, "%s,\"%s\":%s", kvbuf, key, value);
          }
          else           if (strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_value_5G") == 0)
          {
            snprintf(kvbuf, 1792, "%s,\"%s\":%s", kvbuf, key, value);
          }
          else
          {
            snprintf(kvbuf, 1792, "%s,\"%s\":\"%s\"", kvbuf, key, value);
          }
        }
      }
      if (debug_mode > 0)
        printf("jyb test  value %s \n", value);
      free(value);
      value = NULL;
    }
    else
    {
      if (value == NULL)
      {
        if (index++ == 0)
        {
          if (strcmp(key, "InternetGatewayDevice.DeviceInfo.black_url") == 0)
          {
            snprintf(kvbuf, 1792, "\"%s\":[]", key);
          }
          else
          {
            snprintf(kvbuf, 1792, "\"%s\":\"\"", key);
          }
        }
        else
        {
          if (strcmp(key, "InternetGatewayDevice.DeviceInfo.black_url") == 0)
          {
            snprintf(kvbuf, 1792, "%s,\"%s\":[]", kvbuf, key);
          }
          else
          {
            snprintf(kvbuf, 1792, "%s,\"%s\":\"\"", kvbuf, key);
          }
        }
      }
    }

    if (entry == NULL)
    {
      break;
    }
  }
  memset(sendbuf, 0, 2048);
  snprintf(sendbuf, sizeof(sendbuf), GetResponse, deviceMac, kvbuf);

  if (debug_mode > 0)
    printf("tz send mmmmmm %s\n", sendbuf);

  httppost(sendbuf, strlen(sendbuf));
  if (debug_mode > 0)
    printf("tz send mmmmmm  333\n");
  // rc = send(s, sendbuf, strlen(sendbuf), 0);

  return rc;
}

int jsonSetConfig(SOCKET s, json_object *config)
{
  int rc = 0;
  char *tempVal = NULL;
  enum json_type type;
  int index = 0;
  json_object *obj = config;
  int strlenssid = 0;
  char urlComm[256];
  char *pssid = NULL;

  if (config == NULL)
  {
    if (debug_mode > 0)
      printf("jyb test %s\n", config);
    return 0;
  }

  char *key;
  struct json_object *val;
  struct lh_entry *entry = json_object_get_object(obj)->head;

  if (remove(fc_script_set_actions) == 0)
    printf("Removed %s\n", fc_script_set_actions);

  for (; entry != NULL;)
  {
    pssid = NULL;
    if (debug_mode > 0)
      printf("ri mabi\n");
    if (entry)
    {
      key = (char *)entry->k;
      val = (struct json_object *)entry->v;
      entry = entry->next;
    }
    else
    {
      if (debug_mode > 0)
        printf("mabi\n");
      break;
    }
    if (debug_mode > 0)
      printf("tz sfdsfsa mabi\n");
    type = json_object_get_type(val);
    switch (type)
    {
    case json_type_string:
      tempVal = json_object_get_string(val);
      break;
    default:
      break;
    }
    if (debug_mode > 0)
      printf("jyb test 55555555 %s %s\n", key, tempVal);
    if (key != NULL && (!strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_ssid") || !strcmp(key, "InternetGatewayDevice.DeviceInfo.black_url") || !strcmp(key, "InternetGatewayDevice.DeviceInfo.wireless_ssid2")))
    {
      strlenssid = strlen(tempVal);
      pssid = zstream_b64decode(tempVal, &strlenssid);

      if (strlen(pssid) > strlenssid)
      {
        memset(urlComm, 0, 256);
        memcpy(urlComm, pssid, strlenssid);
        tempVal = urlComm;
      }
      else
      {
        tempVal = pssid;
      }
    }

    if (external_set_action_write("value", key, tempVal))
    {
    }
    if (!pssid)
    {
      free(pssid);
    }

    if (entry == NULL)
    {
      break;
    }
  }
  external_set_action_execute();
  if (debug_mode > 0)
    printf("tz exec set ok\n");
  return rc;
}

int read_ver()
{
  FILE *fp = NULL;
  fp=popen(SOFT_VERSION_SHELL,"r"); 
  if(fp== NULL) 
  {
    memset(deviceVer,0,32);
    strcpy(deviceVer,SOFT_VERSION);
    return 0;
  }else{
    memset(deviceVer,0,32);
    fgets(deviceVer,32,fp);  
  }
  pclose(fp);
  return 1;  
}

int read_mac()
{
  FILE *fp = NULL;
  char ch;
  char bufexe[128];
  char buffstr[32];
  memset(deviceMac, 0, 13);
  memset(deviceMacFu, 0, 18);

  if ((fp = fopen("/dev/mtdblock2", "r")) == NULL)
  {

    printf("file cannot be opened/n");
  }
  fgets(buffstr, 32, fp);
  sprintf(deviceMac, "%02X%02X%02X%02X%02X%02X", 0xff & buffstr[4], 0xff & buffstr[5], 0xff & buffstr[6], 0xff & buffstr[7], 0xff & buffstr[8], 0xff & buffstr[9]);
  sprintf(deviceMacFu, "%02X:%02X:%02X:%02X:%02X:%02X", 0xff & buffstr[4], 0xff & buffstr[5], 0xff & buffstr[6], 0xff & buffstr[7], 0xff & buffstr[8], 0xff & buffstr[9]);
  /* 
  deviceMac[0] = buffstr[4];
  deviceMac[1] = buffstr[5];
  deviceMac[2] = buffstr[6];
  deviceMac[3] = buffstr[7];
  deviceMac[4] = buffstr[8];
  deviceMac[5] = buffstr[9];*/

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
    sprintf(cliBuff, "execute command failed: %s", strerror(errno));
    return cliBuff;
  }
  if (NULL != fread(cliBuff, 1, sizeof(cliBuff), fstream))
  {
    if (debug_mode > 0)
      printf("exeShell zhi\n");
    pclose(fstream);
    return cliBuff;
  }
  else
  {
    sprintf(cliBuff, "execute error");
    pclose(fstream);
    return cliBuff;
  }
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

int getMemUsage(int *memtotal, int *memfreeuse)
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
  *memtotal = total;
  *memfreeuse = memfree;

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
  //  printf("tz getRunTime %d\n", timeBuf);
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
  //  printf("tz getRunTime %d %d\n", *total, *used);
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
  //  printf("tz getConnectNum %d\n", total);
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

void set_pifii_report(char *s1_addr, char *s1_port, char *s2_addr, char *s2_port, char *s2_path)
{
  char option[16];
  struct uci_context *ctx = uci_alloc_context(); //申请上下文
  struct uci_ptr ptr = {
      .package = "pifii",
      .section = "server",
      //.option = "value",
      //.value = "256",
  };
  memset(reportServerIp, 0, 32);
  strcpy(reportServerIp, s1_addr);
  memset(reportServerPort, 0, 32);
  strcpy(reportServerPort, s1_port);
  memset(httpPostServerIp, 0, 32);
  strcpy(httpPostServerIp, s2_addr);
  memset(httpPostServerPort, 0, 32);
  strcpy(httpPostServerPort, s2_port);
  memset(httpPostServerPath, 0, 32);
  strcpy(httpPostServerPath, s2_path);

  memset(option, 0, 16);
  strcpy(option, "reportaddr");
  ptr.option = option;
  ptr.value = s1_addr;
  uci_set(ctx, &ptr); //写入配置

  memset(option, 0, 16);
  strcpy(option, "reportport");
  ptr.option = option;
  ptr.value = s1_port;
  uci_set(ctx, &ptr); //

  memset(option, 0, 16);
  strcpy(option, "postaddr");
  ptr.option = option;
  ptr.value = s2_addr;
  uci_set(ctx, &ptr); //写入配置

  memset(option, 0, 16);
  strcpy(option, "postport");
  ptr.option = option;
  ptr.value = s2_port;
  uci_set(ctx, &ptr); //写入配置

  memset(option, 0, 16);
  strcpy(option, "postpath");
  ptr.option = option;
  ptr.value = s2_path;
  uci_set(ctx, &ptr); //写入配置

  uci_commit(ctx, &ptr.p, false); //提交保存更改
  uci_unload(ctx, ptr.p);         //卸载包

  uci_free_context(ctx); //释放上下文
}

int setblackmac(char *p, char *strblackmac)
{
  char tmp[256];
  char *sep = ",";
  char *token = NULL;
  strcpy(tmp, p);
  for (token = strtok(tmp, sep); token != NULL; token = strtok(NULL, sep))
  {
    printf("%s\n", token);
  }
  return 0;
}

void set_pifii_uci(char *enable, char *weekdays, char *blacklist, char *timespan1, char *timespan2, char *timespan3)
{
  char option[16];
  char tempValue[8];
  int rc;
  struct uci_context *ctx = uci_alloc_context(); //申请上下文
  struct uci_ptr ptr = {
      .package = "pifii",
      .section = "server",
      //.option = "value",
      //.value = "256",
  };

  struct uci_ptr ptrO = {
      .package = "pifii",
      .section = "server",
      //.option = "value",
      //.value = "256",
  };
  memset(option, 0, 16);
  strcpy(option, "enable");
  ptr.option = option;
  ptr.value = enable;
  uci_set(ctx, &ptr); //写入配置

  memset(option, 0, 16);
  strcpy(option, "weekdays");
  ptr.option = option;
  ptr.value = weekdays;
  uci_set(ctx, &ptr); //写入配置

  memset(option, 0, 16);
  strcpy(option, "blacklist");
  ptr.option = option;
  ptr.value = blacklist;
  uci_set(ctx, &ptr); //写入配置

  memset(option, 0, 16);
  strcpy(option, "timespan1");
  ptr.option = option;
  ptr.value = timespan1;
  uci_set(ctx, &ptr); //写入配置

  memset(option, 0, 16);
  strcpy(option, "timespan2");
  ptr.option = option;
  ptr.value = timespan2;
  uci_set(ctx, &ptr);             //写入配置
  uci_commit(ctx, &ptr.p, false); //提交保存更改
  uci_unload(ctx, ptr.p);         //卸载包

  memset(option, 0, 16);
  strcpy(option, "timespan3");
  strcpy(tempValue, timespan3);
  ptrO.option = option;
  ptrO.value = tempValue;
  rc = uci_set(ctx, &ptrO);
  //写入配置
  if (debug_mode > 0)
    printf("tz timespan2 %s option=%s %d\n", timespan2, option, rc);
  uci_commit(ctx, &ptrO.p, false); //提交保存更改
  uci_unload(ctx, ptrO.p);         //卸载包

  uci_free_context(ctx); //释放上下文
}

struct msg_st
{
  long int msg_type;
  char text[MAX_TEXT];
};

int sendMsgQ()
{
  int running = 1;
  struct msg_st data;
  int msgid = -1;

  //建立消息队列
  msgid = msgget((key_t)1234, 0666 | IPC_CREAT);
  if (msgid == -1)
  {
    printf("msgget failed with error:\n");
  }

  //向消息队列中写消息，直到写入end

  data.msg_type = 1; //注意2
  strcpy(data.text, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbo");
  //向队列发送数据
  if (msgsnd(msgid, (void *)&data, MAX_TEXT, 0) == -1)
  {
    printf("msgsnd failed\n");
  }
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
  // printf("tz wireless get \n");
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
        //    printf("tz wireless get 223388 %d \n", p.o);
        pWireless->wifidata[0].channel = atoi(p.o->v.string);
      }
    }
  }
  sprintf(buf, "wireless.@wifi-iface[0].portel");
  if (uci_lookup_ptr(c, &p, buf, true))
  {
    //   printf("tz wireless get 23\n");
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
  // printf("tz wireless get 3\n");
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


int getWifinamePassword(char *namepass)
{
   struct uci_context *c;

   WirelessDates pWireless;
  
  c = uci_alloc_context();
  //   printf("tz wireless 22\n");
  wirelessConfig(c, &pWireless);

  uci_free_context(c);
  
  sprintf(namepass,"+OK=%s,%s\n",  pWireless.wifidata[0].ssid,pWireless.wifidata[0].password);
  

  return 1;
}

void returnReportInfo(char *reportMsg)
{
  sprintf(reportMsg, "\"reportaddr\":\"%s\",\"reportport\":\"%s\",\"postaddr\":\"%s\",\"postport\":\"%s\",\"postpath\":\"%s\"",
          reportServerIp, reportServerPort, httpPostServerIp, httpPostServerPort, httpPostServerPath);
}

int getUciValue(struct uci_context *c, char *key, char *value)
{
  char buf[64];
  struct uci_ptr p;
  sprintf(buf, "pifii.server.%s", key);
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    sprintf(value, "");
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(value, p.o->v.string);
    }
    else
    {
      sprintf(value, "");
    }
  }

  return 1;
}

void returnBlackMac(char *reportMsg)
{
  char enable[10];
  char weekdays[10];
  char blacklist[256];
  char timespan1[10];
  char timespan2[10];
  char timespan3[10];

  char buf[64];
  struct uci_context *c = uci_alloc_context();

  getUciValue(c, "enable", enable);
  getUciValue(c, "weekdays", weekdays);
  getUciValue(c, "blacklist", blacklist);
  getUciValue(c, "timespan1", timespan1);
  getUciValue(c, "timespan2", timespan2);
  getUciValue(c, "timespan3", timespan3);

  uci_free_context(c);

  sprintf(reportMsg, "\"enable\":\"%s\",\"weekdays\":\"%s\",\"blacklist\":\"%s\",\"timespan1\":\"%s\",\"timespan2\":\"%s\",\"timespan3\":\"%s\"",
          enable, weekdays, blacklist, timespan1, timespan2, timespan3);
}

void initReportConfig(struct uci_context *c)
{
  char buf[64];
  struct uci_ptr p;

  sprintf(buf, "pifii.server.devicetype");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    sprintf(deviceType, DEVICE_TYPE_E);
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(deviceType, p.o->v.string);
    }
    else
    {
      sprintf(deviceType, DEVICE_TYPE_E);
    }
  }

  sprintf(buf, "pifii.server.reportaddr");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    sprintf(reportServerIp, SERVER_IP);
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(reportServerIp, p.o->v.string);
    }
    else
    {
      sprintf(reportServerIp, SERVER_IP);
    }
  }

  sprintf(buf, "pifii.server.reportport");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    sprintf(reportServerPort, SERVER_PORT);
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(reportServerPort, p.o->v.string);
    }
    else
    {
      sprintf(reportServerPort, SERVER_PORT);
    }
  }
  sprintf(buf, "pifii.server.postaddr");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    sprintf(httpPostServerIp, HTTPPOST_IP);
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(httpPostServerIp, p.o->v.string);
    }
    else
    {
      sprintf(httpPostServerIp, HTTPPOST_IP);
    }
  }

  sprintf(buf, "pifii.server.postport");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    sprintf(httpPostServerPort, HTTPPOST_PORT);
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(httpPostServerPort, p.o->v.string);
    }
    else
    {
      sprintf(httpPostServerPort, HTTPPOST_PORT);
    }
  }
  sprintf(buf, "pifii.server.postpath");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    sprintf(httpPostServerPath, HTTPPOST_PORT);
  }
  else
  {
    if (p.o != NULL)
    {
      sprintf(httpPostServerPath, p.o->v.string);
    }
    else
    {
      sprintf(httpPostServerPath, HTTPPOST_PATH);
    }
  }
}
/*
int threadHome()
{
  int client_socket_fd;
  char recvData[1024];
  char sendData[1024];
  char tempstr[1500];

  int id = 1;
  json_object *pobj, *p1_obj, *p2_obj, *p3_obj = NULL;

  char *param_p1, *param_p2, *param_p3, *param_p4, *param_p5 = NULL;

  char *hsid,*hid,*hver,*hcmdtype;

  int param_int;

  char *typeE, *name, *command;

  char *dataE;

  int typeInt;

  int datalength;

    int len = 0;

  json_object *new_obj;

  int length;
  int rc;
  int commandId;

  int server_socket_fd = socket(AF_INET, SOCK_DGRAM, 0); 
  if(server_socket_fd == -1) 
  { 
    perror("Create Socket Failed:"); 
    exit(1); 
  } 
  

  if(-1 == (bind(server_socket_fd,(struct sockaddr*)&server_addr,sizeof(server_addr)))) 
  { 
    perror("Server Bind Failed:"); 
    exit(1); 
  } 

      struct sockaddr_in client_addr; 
    socklen_t client_addr_length = sizeof(client_addr); 

  
  while(1) {
    memset(recvData, 0, 4096);
    if(recvfrom(server_socket_fd, recvData, sizeof(recvData),0,(struct sockaddr*)&client_addr, &client_addr_length) == -1) 
    { 
    printf("tz 888%s\n", recvData);
    //     new_obj = json_tokener_parse(TestJson);
    new_obj = json_tokener_parse(recvData);
    if (is_error(new_obj))
    {
      printf("tz error para%s\n");
      // rc = send(s, ErrorJson, sizeof(ErrorJson), 0);
    }
    else
    {

      hsid = GetValByEtype(new_obj, "sid");
      hid = GetValByEtype(new_obj, "id");
      hver = GetValByEtype(new_obj, "ver");
      hcmdtype = GetValByEtype(new_obj, "cmdtype");
      //typeE = GetValByEtype(new_obj, "params");
      printf("tz name %s\n", name);
      if (hsid == NULL||hid==NULL||hver==NULL||hcmdtype==NULL)
      {
        
        //发送  的json 错误
      }
      else if (!strcmp(hcmdtype, "4097"))
      {
            memset(sendData,0,1024);
            sprintf(sendData,HomeResponse,hsid,hid,hver);
            if (sendto(server_socket_fd, sendData, strlen(sendData), 0, (struct sockaddr*)&client_addr, client_addr_length)) < 0)
            {
              printf("Send File Name Failed:");
        
            }
            else{
              printf("Send ok\n");
            }
      }
      else if (!strcmp(hcmdtype, "get"))
      {
 
      }
      else if (!strcmp(hcmdtype, "set"))
      {
 
      }
      else
      {

      }
      json_object_put(new_obj);
    }
  }
  
}
*/
int check_image_name(char *name)
{
  int length = 0;
  char tempName[32];

  if (name == NULL)
  {
    return 0;
  }
  else
  {

    if (!strcmp(deviceType, "IJLY_410"))
    {
      if (strstr(name, "D12_7628n_8m_IJLY410") != NULL)
      {
        return 1;
      }
      else
      {
        return 0;
      }
    }
    else if (!strcmp(deviceType, "IJLY_420"))
    {
      if (strstr(name, "D11_7628n_16m_IJLY420") != NULL)
      {
        return 1;
      }
      else
      {
        return 0;
      }
    }
    else if (!strcmp(deviceType, "ZLT P11(IDU)"))
    {
      if (strstr(name, "D12_7628n_8m_P11") != NULL)
      {
        return 1;
      }
      else
      {
        return 0;
      }
    }
    else
    {
      return 0;
    }
  }
  return 1;
}


time_t savetime;
int   startStudy;
int   sameIndex;
char  studyData[5][16];

int setStrudyLed(int enable)
{
  FILE *fp = NULL;
  char buf[64];
  if(enable == 1)
  {
      sprintf(buf,"echo \"%d\" >/sys/class/leds/wifi/brightness",0);
  }else{
      sprintf(buf,"echo \"%d\" >/sys/class/leds/wifi/brightness",1);
  }
  fp=popen(buf,"r"); 
  if(fp== NULL) 
  {
     return 1;
  }
  else{
    return 0;
  }
}

int initStrudyDate()
{
    startStudy = 0;
    sameIndex = 0;
}

int setStrudyDate(int enable)
{
    setStrudyLed(enable);
    if(enable == 0)
    {
       savetime   = 0;
       startStudy = 0;
       sameIndex  = 0;
    }
    else 
    {
       savetime   = time(NULL);
       sameIndex  = 0;
       startStudy = 1;
    }
}

int strudyDateMode(char *data)
{
     //30秒内收到相同报文
     time_t intime;

     if((0xff&data[5])== 0x03)
     {
       setStrudyDate(1);
       return 0;
     }

     if(startStudy == 0)
     {
       sameIndex = 0;
       return 0;
     }
     
     intime = time(NULL);
     printf("jiangyibo wwwwww111 11111\n");
     if(intime - savetime > 30)
     {
          printf("jiangyibo wwwwww111 222\n");
          setStrudyDate(0);
          return 0;
     }else{
         if(sameIndex ++ >= 3)
         {
           printf("jiangyibo wwwwww111  3333\n");
           setStrudyDate(0);
           return 1;
         }else{
           printf("jiangyibo wwwwww111  44444\n");
           return 0;
         }
     }
/*
     if(startStudy== 1)
     {
         savetime = intime;
         snprintf(studyData,16,data);
     }else if(startStudy >= 4)
     {
          startStudy = 0;
     }
     else 
     {
          if(!strcmp(studyData,data))
          {
            return 1;
          }
     }
     return 1;
*/     
}

int safeGateDate(char *data,int length,int client_socket_fd, struct sockaddr_in server_addr)
{
  char sendmsgData[512];  
  char anfangid[10];
  int  i = 0;
  int  index = 0;
  int  rc;
  int  ishave ;
  char smarttype;

  memset(sendmsgData,0,512);



  socklen_t server_addr_length = sizeof(server_addr);
  printf("Send to safeDev HB ID ok %02X%02X%02X\n",data[0],data[1],data[2]);
  if(data[0]==11)
  {
     //recive request ssid, send ssid
    if(length == 9)
    {
      getWifinamePassword(sendmsgData);
      printf("jiangyibo ssid %s\n",sendmsgData);
//      sprintf(sendmsgData,"+OK=%s,%s\n","ihome-fd0cdc","12345678");
      if (sendto(client_socket_fd, sendmsgData, strlen(sendmsgData), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
      {
        printf("Send File Name Failed:");
      }
      else
      {
        if (debug_mode > 0)
          printf("Send to safeDev ssid  ok\n");
      }
    }
    return 1;
  }
  else if(data[0]==0xa||data[0]==0x9){
      

    // recive heartbear
    return 1;
  }
  else if(data[0]==0xc){
    // recive heartbear

      memset(sendmsgData,0,512);
      sprintf(sendmsgData,"%02X%02X",data[1],data[2]);
      sprintf(anfangid,"%02X%02X",data[1],data[2]);
      
      AddHomeDeviceShort(sendmsgData, server_addr.sin_addr.s_addr,htons(server_addr.sin_port) ,"3","2","1");
      sprintf(sendmsgData,"+OK\r\n");
      if (sendto(client_socket_fd, sendmsgData, strlen(sendmsgData), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
      {
        printf("Send File Name Failed:");
      }
      else
      {
        if (debug_mode > 0)
          printf("Send to safeDev HB ok port= %d\n",htons(server_addr.sin_port));
      }
      rc = sendCheckSmartDev(anfangid,sendmsgData);
      if( rc == 1 && index==0)
      {
          httppost(sendmsgData, strlen(sendmsgData));
          if(index++ > 30)
          {
            index = 0;
          }
      }

      return 1;
  }  
  else if(data[0]==0x0d&&length==8){
      // recive deve alarm
      memset(sendmsgData,0,128);

      sprintf(sendmsgData,"+OK\r\n");
      if (sendto(client_socket_fd, sendmsgData, strlen(sendmsgData), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
      {
        printf("Send File Name Failed:");
      }
      else
      {
        if (debug_mode > 0)
          printf("Send to safeDev alarm ok\n");
      }

      if (debug_mode > 0)
        printf("tz send mmmmmm %s\n", sendmsgData);

      rc =   findSmartDevArray( &data[1],&data[3] ,&data[5] );
      if(rc == 0)
      {
            return 2;
      }

      ishave = strudyDateMode(data);

      if( ishave == 1 )  // duima mode add device
      {
          printf("jiangyibo wwwwww111 11111 66666\n");
          sprintf(anfangid,"%02X%02X",data[1],data[2]);
          rc =  findSmartDevArrayAdd( &data[1],&data[3] ,&data[5] );
          rc = sendCheckSmartDev(anfangid,sendmsgData);
          httppost(sendmsgData, strlen(sendmsgData));
        
      }else if(startStudy == 0){
        printf("jiangyibo wwwwww111 11111 77777\n");


            //send to smart center
            memset(sendmsgData,0,128);
            smartDevToCenter(data,sendmsgData);
            sleep(1);
           
            
            if (sendto(client_socket_fd, sendmsgData, strlen(sendmsgData), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
            {
              printf("Send Command Failed:");
            }
            else
            {
              if (debug_mode > 0)
                printf("Send Command safeDev alarm ok %s\n",sendmsgData);
            }
            
            //post to smart center
            memset(sendmsgData,0,128);
            smarttype =   smartDevType(&data[5]);
            sprintf(sendmsgData, SafeDevTrap,0xff & data[1],0xff &data[2], smarttype ,0xff &data[3],0xff &data[4],0xff &data[5],deviceMac);
            httppost(sendmsgData, strlen(sendmsgData));
        
      }


      if (debug_mode > 0)
        printf("tz send mmmmmm  333\n");
 
      return 2;
  }  
  else{
    // recive other 
    return 0;
  }
}

int threadUdp(int *socket_fd)
{
  int client_socket_fd = *socket_fd;
  char recvData[4096];
  char sendmsgData[1500];
  char tempstr[2048];
  char *wificlient = NULL;
  int uptime;

  int id = 1;
  json_object *pobj, *p1_obj, *p2_obj, *p3_obj = NULL;

  char *param_p1, *param_p2, *param_p3, *param_p4, *param_p5 = NULL, *param_p6;

  char *hsid, *hid, *hver, *hcmdtype, *hdevtype;
  int dns_ok = 1;

  int hstatstr;

  int param_int;
  int checkName;

  char *typeE, *name, *command;

  char *dataE;

  int typeInt;

  int datalength;

  int len = 0;

  json_object *new_obj;

  int length;
  int rc;
  int commandId;

  struct sockaddr_in server_addr;
  bzero(&server_addr, sizeof(server_addr));
  socklen_t server_addr_length = sizeof(server_addr);
  while (1)
  {
    bzero(&server_addr, sizeof(server_addr));
    server_addr_length = sizeof(server_addr);
    memset(recvData, 0, 4096);
    if ((len = recvfrom(client_socket_fd, recvData, sizeof(recvData), 0, (struct sockaddr *)&server_addr, &server_addr_length)) > 0)
    {
      if (debug_mode > 0)
        printf("tz recv%s\n", recvData);

      rc = safeGateDate(recvData,len,client_socket_fd,server_addr);

      if(rc > 0)
      {
        continue ;
      }
      //     new_obj = json_tokener_parse(TestJson);
      new_obj = json_tokener_parse(recvData);
      if (debug_mode > 0)
        printf("tz recv 333%s\n", recvData);
      if (new_obj == NULL || is_error(new_obj))
      {
        if (debug_mode > 0)
          printf("tz error para\n");
        // rc = send(s, ErrorJson, sizeof(ErrorJson), 0);
      }
      else
      {
        name = NULL;
       printf("tz recv name smartdevice dsfdsa\n");
        name = GetValByEtype(new_obj, "name");

        //typeE = GetValByEtype(new_obj, "params");
        if (debug_mode > 0)
          printf("tz recv name smartdevice\n");
        if (name == NULL)
        {
          //rc = send(client_socket_fd, ErrorJson, sizeof(ErrorJson), 0);
          //发送  的json 错误
        //  printf("tz recv name smartdevice 22\n");
          hsid = GetValByEtype(new_obj, "sid");
          hid = GetValByEtype(new_obj, "id");
          hver = GetValByEtype(new_obj, "ver");
          hcmdtype = GetValByEtype(new_obj, "cmdtype");

          if (hsid == NULL || hid == NULL || hver == NULL || hcmdtype == NULL)
          {

            //发送  的json 错误
          }
          else if (!strcmp(hcmdtype, "4097"))
          {
            //
            hdevtype = GetValByEtype(new_obj, "devtype");
            hver = GetValByEtype(new_obj, "ver");
            hstatstr = GetBoolByEtype(new_obj, "devicestate");
            
            if (hstatstr == 1)
            {
              AddHomeDevice(hid, server_addr.sin_addr.s_addr, hdevtype,hver ,"1");
            }
            else
            {
              AddHomeDevice(hid, server_addr.sin_addr.s_addr, hdevtype, hver,"0");
            }

            memset(sendmsgData, 0, 1500);
            //  sprintf(sendmsgData, HomeSwitchOn, hid, hver);
            sprintf(sendmsgData, HomeResponse, "1", hid, hver);
            //           printf("tz recv name ok %s\n",sendmsgData);
            server_addr.sin_port = htons(HOMEDEV_PORT);
            //  printf("tz recv name smartdevice3 44 %s %s %s\n",hsid,hid,hver);
            if (debug_mode > 0)
              printf("tz homedevice %s\n", sendmsgData);
            if (sendto(client_socket_fd, sendmsgData, strlen(sendmsgData), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
            {
              printf("Send File Name Failed:");
            }
            else
            {
              if (debug_mode > 0)
                printf("Send ok\n");
            }
          }
          else if (!strcmp(hcmdtype, "4"))
          {
            dns_ok = setnameserver(&(server_addr.sin_addr.s_addr), reportServerIp);
            server_addr.sin_port = htons(HOMEDEV_PORT);
            if (dns_ok == 1)
            {
              //  printf("tz recv name smartdevice3 44 %s %s %s\n",hsid,hid,hver);
              if (debug_mode > 0)
                printf("tz homedevice %s\n", sendmsgData);
              if (sendto(client_socket_fd, recvData, strlen(recvData), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
              {
                printf("Send File Name Failed:");
              }
              else
              {
                if (debug_mode > 0)
                  printf("Send ok\n");
              }
            }
          }
          else if (!strcmp(hcmdtype, "4099") || !strcmp(hcmdtype, "5001") || !strcmp(hcmdtype, "5002") || !strcmp(hcmdtype, "5003")) //重启
          {
            // commandSendtoHomeDevice(client_socket_fd, hid, recvData);
          }
          else
          {
          }
        }
        else if (!strcmp(name, "informResponse"))
        {
          if (debug_mode > 0)
            printf("jyb test 11 %d\n", commandId);
          commandId = GetIntByEtype(new_obj, "commandEvent");
          if (debug_mode > 0)
            printf("jyb test 11 %d\n", commandId);
          if (commandId == 0)
          {
           // printf("jyb bbbbbb test 11\n");
            //   if (pReal->tr069state == 3)
            {
              //exeShell("/etc/init.d/freecwmpd stop&");
            }
          }
          else if (commandId == 1)
          {
            // if (pReal->tr069state == 4)
            {
              // exeShell("/etc/init.d/freecwmpd start&");
            }
          }
          else if (commandId == 5)
          {
            //if (pReal->tr069state == 3)
            {
              // exeShell("/etc/init.d/freecwmpd stop&");
            }
          }
          else if (commandId == 6)
          {

            system("reboot -f");
          }
          else if (commandId == 7)
          {

            system("uci set pifii.register.udpport=1&&uci commit pifii");
          }
          else if (commandId == 8)
          {
            system("/usr/sbin/updateUdpReport.sh &");
          }
          else
          {
          }
          //发送  的定时上报报文
        }
        else if (!strcmp(name, "get"))
        {
          command = GetValByEtype(new_obj, "keyname");
          if (command == NULL)
          {
          }
          else if (strcmp(command, "config") == 0)
          {
            p1_obj = json_object_object_get(new_obj, "packet");
            jsonGetConfig(client_socket_fd, p1_obj);
          }
          else if (strcmp(command, "getvalue") == 0)
          {
            memset(sendmsgData, 0, 1500);
            getFileData(tempstr, "config.json");
            sprintf(sendmsgData, ConfigJson, deviceMac, tempstr);
            rc = send(client_socket_fd, (char *)sendmsgData, sizeof(sendmsgData), 0);
          }
          else if (strcmp(command, "inform") == 0)
          {
            int indate = 0, outdate = 0;
            int memtotal = 0;
            int memfreeuse = 0;
            int flashload = 0;
            int flashuse = 0;
            getDeviceSpeed(&indate, &outdate);
            memset(tempstr, 0, 2048);
            if (external_get_action("value", "InternetGatewayDevice.LANDevice.1.Wireless.WiFiClient", &wificlient) == 0)
            {
              if (debug_mode > 0)
                printf("tz wificlient %s\n", wificlient);
            }
            uptime = getRunTime();
            //            cpuload = getCpuUsage();
            if (!strcmp(deviceType, "IJLY_410"))
            {
              flashload = 8 * 1024;
              flashuse = 5123;
            }
            else if (!strcmp(deviceType, "IJLY_410"))
            {
              flashload = 16 * 1024;
              flashuse = 6123;
            }
            else
            {
              flashload = 8 * 1024;
              flashuse = 5123;
            }

            getMemUsage(&memtotal, &memfreeuse);
            if (wificlient == NULL)
            {
              sprintf(tempstr, informRes, deviceMac, deviceMac, deviceType, HARD_VERSION, deviceVer, 20, memfreeuse, memtotal, flashuse, flashload, uptime, indate, outdate, "[]");
              free(wificlient);
              wificlient = NULL;
              httppost(tempstr, strlen(tempstr));
            }
            else
            {
              sprintf(tempstr, informRes, deviceMac, deviceMac, deviceType, HARD_VERSION, deviceVer, 20, memfreeuse, memtotal, flashuse, flashload, uptime, indate, outdate, wificlient);
              free(wificlient);
              wificlient = NULL;
              httppost(tempstr, strlen(tempstr));
            }
          }
          else if (!strcmp(command, "blackmac"))
          {
            memset(sendmsgData, 0, 1500);
            returnBlackMac(sendmsgData);
            sprintf(tempstr, GetBlackmac, deviceMac, sendmsgData);
            httppost(tempstr, strlen(tempstr));
          }
          else if (!strcmp(command, "appblackmac"))
          {
            memset(sendmsgData, 0, 1500);
            returnBlackMac(sendmsgData);
            sprintf(tempstr, GetBlackmac, deviceMac, sendmsgData);
            server_addr.sin_port = htons(ROUTER_PORT);
            if (sendto(client_socket_fd, tempstr, strlen(tempstr), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
            {
              printf("Send File Name Failed:");
            }
          }
          else if (strcmp(command, "reportconfig") == 0)
          {
            memset(sendmsgData, 0, 1500);
            returnReportInfo(sendmsgData);
            sprintf(tempstr, GetReport, deviceMac, sendmsgData);
            httppost(tempstr, strlen(tempstr));
          }
          else if (strcmp(command, "command") == 0)
          {
            memset(sendmsgData, 0, 1024);
            p1_obj = GetValByEdata(new_obj, "packet");
            param_p1 = GetValByKey(p1_obj, "shellcmd");
            param_p2 = exeShell(param_p1);
            length = strlen(param_p2);
            param_p3 = zstream_b64encode(param_p2, &length);
            if (debug_mode > 0)
              printf("tz %s\n", param_p3);
            sprintf(sendmsgData, CommandJson, deviceMac, param_p3);
            free(param_p3);
            rc = send(client_socket_fd, (char *)sendmsgData, sizeof(sendmsgData), 0);
          }
          else if (strcmp(command, "file") == 0)
          {
            memset(sendmsgData, 0, 1500);
            p1_obj = GetValByEdata(new_obj, "packet");
            param_p1 = GetValByKey(p1_obj, "shellcmd");
            if (debug_mode > 0)
              printf("jyb test %s\n", param_p1);
            if (param_p1 != NULL)
            {
              if (getConfigFile(tempstr, param_p1) != 0)
              {
                length = strlen(tempstr);
                param_p3 = zstream_b64encode(tempstr, &length);

                memset(sendmsgData, 0, 1500);
                sprintf(sendmsgData, FileJson, deviceMac, param_p1, param_p3);
                free(param_p3);
                // rc = send(client_socket_fd, (char *)sendmsgData, sizeof(sendmsgData), 0);
              }
              else
              {
                memset(sendmsgData, 0, 1500);
                // rc = send(client_socket_fd, ErrorJson, sizeof(ErrorJson), 0);
              }
            }
          }
          else
          {
            memset(sendmsgData, 0, 1500);
            rc = send(client_socket_fd, ErrorJson, sizeof(ErrorJson), 0);
          }
        }
        else if (!strcmp(name, "set"))
        {
          char *c = NULL;

          command = GetValByEtype(new_obj, "keyname");
          if (debug_mode > 0)
            printf("tz eeee 333 %s\n", command);
          if (!strcmp(command, "config"))
          {
            p1_obj = json_object_object_get(new_obj, "packet");
            jsonSetConfig(client_socket_fd, p1_obj);
            if (debug_mode > 0)
              printf("jyb test ok\n");
            memset(tempstr, 0, 1024);
            sprintf(tempstr, SetResponse, deviceMac, command, "setok");
            httppost(tempstr, strlen(tempstr));
          }
          else if (!strcmp(command, "reboot"))
          {
            memset(tempstr, 0, 1024);
            sprintf(tempstr, SetResponse, deviceMac, command, "setok");
            httppost(tempstr, strlen(tempstr));
            system("reboot");
          }
          else if (!strcmp(command, "homesecuritylist"))
          {
            p1_obj = json_object_object_get(new_obj, "packet");
            memset(tempstr, 0, 1024);
            sprintf(tempstr, SetResponse, deviceMac, command, "setok");
            httppost(tempstr, strlen(tempstr));
            procSmartDevArray(p1_obj);
          }
          else if (!strcmp(command, "download"))
          {
            memset(tempstr, 0, 1024);

            p1_obj = GetValByEdata(new_obj, "packet");
            param_p1 = GetValByKey(p1_obj, "url");
            param_p2 = GetValByKey(p1_obj, "FileSize");
            checkName = check_image_name(param_p1);
            if (param_p1 != NULL && checkName == 1)
            {
              sprintf(tempstr, DownloadResponse, deviceMac, command, "setok", deviceType, "CMTT", "1");
              httppost(tempstr, strlen(tempstr));
              commandDownload(param_p1, param_p2);
            }
            else
            {
              sprintf(tempstr, DownloadResponse, deviceMac, command, "setok", deviceType, "CMTT", "2");
              httppost(tempstr, strlen(tempstr));
            }
          }
          else if (!strcmp(command, "factory"))
          {
            memset(tempstr, 0, 1024);
            sprintf(tempstr, SetResponse, deviceMac, command, "setok");
            httppost(tempstr, strlen(tempstr));

            commandFactoryset();
          }
          else if (!strcmp(command, "sysupgrade"))
          {
            memset(tempstr, 0, 1024);
            sprintf(tempstr, SetResponse, deviceMac, command, "setok");
            httppost(tempstr, strlen(tempstr));

            p1_obj = GetValByEdata(new_obj, "packet");
            param_p1 = GetValByKey(p1_obj, "url");
            param_p2 = GetValByKey(p1_obj, "size");
            system("/usr/sbin/updateUdpReport.sh &");
          }
          else if (!strcmp(command, "reportconfig"))
          {
            memset(tempstr, 0, 1024);
            sprintf(tempstr, SetResponse, deviceMac, command, "setok");
            httppost(tempstr, strlen(tempstr));

            p1_obj = GetValByEdata(new_obj, "packet");
            param_p1 = GetValByKey(p1_obj, "reportaddr");
            param_p2 = GetValByKey(p1_obj, "reportport");
            param_p3 = GetValByKey(p1_obj, "postaddr");
            param_p4 = GetValByKey(p1_obj, "postport");
            param_p5 = GetValByKey(p1_obj, "postpath");
            set_pifii_report(param_p1, param_p2, param_p3, param_p4, param_p5);
          }
          else if (!strcmp(command, "homedevice"))
          {
            memset(tempstr, 0, 1024);
            sprintf(tempstr, DownloadResponse, deviceMac, command, "setok", "IJLY_410", "CMTT", "1");
            httppost(tempstr, strlen(tempstr));
          }
          else if (!strcmp(command, "blackmac"))
          {

            memset(tempstr, 0, 1024);
            sprintf(tempstr, SetResponse, deviceMac, command, "setok");
            httppost(tempstr, strlen(tempstr));
            if (debug_mode > 0)
              printf("tz blackmac oooo\n");
            p1_obj = GetValByEdata(new_obj, "packet");
            param_p1 = GetValByKey(p1_obj, "enable");
            param_p2 = GetValByKey(p1_obj, "weekdays");
            param_p3 = GetValByKey(p1_obj, "blacklist");
            param_p4 = GetValByKey(p1_obj, "timespan1");
            param_p5 = GetValByKey(p1_obj, "timespan2");
            param_p6 = GetValByKey(p1_obj, "timespan3");
            if (debug_mode > 0)
              printf("tz blackmac oooo 222 \n");
            set_pifii_uci(param_p1, param_p2, param_p3, param_p4, param_p5, param_p6);
            sendMsgQ();
          }
          else if (!strcmp(command, "appblackmac"))
          {

            memset(tempstr, 0, 1024);
            sprintf(tempstr, SetResponse, deviceMac, command, "setok");
            if (debug_mode > 0)
              printf("tz appblackmac send %s\n", inet_ntoa(server_addr.sin_addr));
            // server_addr.sin_addr.s_addr = inet_addr("192.168.3.68");
            server_addr.sin_port = htons(ROUTER_PORT);
            if (sendto(client_socket_fd, tempstr, strlen(tempstr), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
            {
              printf("Send File Name Failed:");
            }
            if (debug_mode > 0)
              printf("tz blackmac oooo\n");
            p1_obj = GetValByEdata(new_obj, "packet");
            param_p1 = GetValByKey(p1_obj, "enable");
            param_p2 = GetValByKey(p1_obj, "weekdays");
            param_p3 = GetValByKey(p1_obj, "blacklist");
            param_p4 = GetValByKey(p1_obj, "timespan1");
            param_p5 = GetValByKey(p1_obj, "timespan2");
            param_p6 = GetValByKey(p1_obj, "timespan3");
            if (debug_mode > 0)
              printf("tz blackmac oooo 222 %s mmm %s jiang\n", param_p5, param_p6);
            set_pifii_uci(param_p1, param_p2, param_p3, param_p4, param_p5, param_p6);
            sendMsgQ();
          }
          else
          {

            //rc = send(client_socket_fd, ErrorJson, sizeof(ErrorJson), 0);
          }
        }
        else if (!strcmp(name, "homesmart"))
        {
          char *c = NULL;

          command = GetValByEtype(new_obj, "keyname");
          if (debug_mode > 0)
            printf("tz eeee 333 %s\n", command);
          if (!strcmp(command, "set"))
          {

            hid = GetValByEtype(new_obj, "smartid");
            p1_obj = GetValByEdata(new_obj, "packet");
            if(p1_obj== NULL)
            {
               printf("send homesmart command %s\n", hid);
            }
            
            if (hid != NULL)
            {
                  param_p1 = GetValByKey(p1_obj, "cmdtype");
                  param_p3 = GetValByKey(p1_obj, "devtype");

                  memset(sendmsgData, 0, 1500);
                  sprintf(sendmsgData, HomeRespApp);
                  server_addr.sin_port = htons(HOMEDEV_PORT);
                  //  printf("tz recv name smartdevice3 44 %s %s %s\n",hsid,hid,hver);
                  if (debug_mode > 0)
                    printf("tz send xuewen %s\n", sendmsgData);
                  if (sendto(client_socket_fd, sendmsgData, strlen(sendmsgData), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
                  {
                    printf("Send File Name Failed:");
                  }
                  else
                  {
                    if (debug_mode > 0)
                      printf("Send app ok\n");
                  }
                printf("send homesmart command %s\n", command);
                if(param_p3!=NULL&&!strcmp(param_p3,"3"))
                {

                      if(param_p1!=NULL&&!strcmp(param_p1,"5004"))
                      {
                          param_p2 = GetValByKey(p1_obj, "value");
                          if(startDev!=NULL)
                          {
                            startDev->state = 0xC0;
                          }
                          memset(tempstr, 0, 1024);
                          sprintf(tempstr,"%s\r\n",param_p2);
                          commandSendtoHomeDevicePort(client_socket_fd, hid,tempstr );
                      } 
                      else if(param_p1!=NULL&&!strcmp(param_p1,"5005"))
                      {
                          param_p2 = GetValByKey(p1_obj, "value");
                          if(startDev!=NULL)
                          {
                            startDev->state = 0x0C;
                          }
                          memset(tempstr, 0, 1024);
                          sprintf(tempstr,"%s\r\n",param_p2);
                          commandSendtoHomeDevicePort(client_socket_fd, hid,tempstr );
                      }
                      else if(param_p1!=NULL&&!strcmp(param_p1,"5006"))
                      {
                         setStrudyDate(1);
                      }
                      else{
                          param_p2 = GetValByKey(p1_obj, "value");
                          memset(tempstr, 0, 1024);
                          sprintf(tempstr,"%s\r\n",param_p2);
                          commandSendtoHomeDevicePort(client_socket_fd, hid,tempstr );
                      }
                }
                else {
                commandSendtoHomeDevice(client_socket_fd, hid, json_object_to_json_string(p1_obj));
                }
              //发送  的json 错误
            }
          }
        }
        else
        {

          // rc = send(client_socket_fd, ErrorJson, sizeof(ErrorJson), 0);
          //发送   的json 错误
        }
        json_object_put(new_obj);
      }
    }
  }
}

int get_gw_ip(char *eth, char *ipaddr)
{
  int sock_fd;
  struct sockaddr_in my_addr;
  struct ifreq ifr;

  /**/ /* Get socket file descriptor */
  if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
  {
    return 0;
  }

  /**/ /* Get IP Address */
  strncpy(ifr.ifr_name, eth, IF_NAMESIZE);
  ifr.ifr_name[IFNAMSIZ - 1] = '/0';

  if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0)
  {

    return 0;
  }

  memcpy(&my_addr, &ifr.ifr_addr, sizeof(my_addr));
  strcpy(ipaddr, inet_ntoa(my_addr.sin_addr));
  close(sock_fd);
  return 1;
}

int setnameserver(int *value, char *NET_IP)
{
  //获取联网状态
  struct hostent *host;
  int inaddr = 1;
  struct in_addr *ipaddr;
  /*判断是主机名还是ip地址*/
  inaddr = inet_addr(NET_IP);
  if (inaddr == INADDR_NONE)
  {
    if ((host = gethostbyname(NET_IP)) == NULL) /*是主机名*/
    {
      printf("dns chucuo\n");
      *value = inet_addr("113.98.195.201");
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

int getRegisterState()
{
  struct uci_context *c;
  char buf[128];
  struct uci_ptr p;
  int value = 0;

  c = uci_alloc_context();
  sprintf(buf, "pifii.register.device_id");
  if (UCI_OK != uci_lookup_ptr(c, &p, buf, true))
  {
    value = 0;
  }
  else
  {
    if (p.o != NULL)
    {
      value = 1;
    }
  }

  uci_free_context(c);
  return value;
}

int main(int argc, char *argv[])
{
  char infomsg[1500];
  char commandkey[] = "inform";
  char sendData[1500];
  char strhomeState[1500];
  char wanIpaddr[32];
  int uptime = 0;
  int registState = 0;
  int cpuload = 0;
  int length;
  int rc;
  int commandId;
  int i;
  int ret;
  pthread_t id1, id2;

  if (argc >= 2)
  {
    debug_mode = 1;
  }

  // sigInit();
  initStrudyDate();
  read_mac();
  read_ver();
  initHomeDevice();
  initSmartDevArray();
  pthread_mutex_init(&mutex, NULL);

  memset(informRes, 0, 1500);
  memset(infomsg, 0, 1500);
  getFileData(infomsg, "inform.json");
  getFileData(informRes, "informResponse.json");

  if (debug_mode > 0)
    printf("send ok tit\n");

  int id = 0;

  SendPack sendmsg;
  int index = 0;
  char *p;
  RealTimeDate *pReal;
  WirelessDates *pWireless;
  NetworkDate *pNet;

  struct uci_context *c;

  pReal = sendmsg.data;
  pWireless = sendmsg.data + sizeof(RealTimeDate);
  pNet = sendmsg.data + sizeof(RealTimeDate) + sizeof(WirelessDates);

  sendmsg.version = APP_VERSION;
  sendmsg.id = 222;
  memcpy(sendmsg.devid, deviceMac, 6);
  sendmsg.bufsize = 1500;
  sprintf(pReal->equipment, "TZ");
  sprintf(pReal->hardwaretype, "PF308-TZ-H");
  sprintf(pReal->softwaretype, "1.6.12");

  pReal->aprouter = 1;
  pWireless->wifinum = 1;

  sendmsg.version = APP_VERSION;

  /* 服务端地址 */
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  bzero(&server_addr, sizeof(server_addr));
  bzero(&client_addr, sizeof(client_addr));
  server_addr.sin_family = AF_INET;

  socklen_t server_addr_length = sizeof(server_addr);

  /* 创建socket */
  int client_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (client_socket_fd < 0)
  {
    perror("Create Socket Failed:");
    exit(1);
  }

  client_addr.sin_family = AF_INET;
  client_addr.sin_port = htons(ROUTER_PORT);
  client_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  /* 绑定 */
  if (-1 == (bind(client_socket_fd, (struct sockaddr *)&client_addr, sizeof(client_addr))))
  {
    printf("Server Bind error\n");
  }

  struct timeval timeout = {5, 0};
  setsockopt(client_socket_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
  setsockopt(client_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

  RecvPack pack_info;

  ret = pthread_create(&id1, NULL, (void *)threadUdp, &client_socket_fd); //创建线程1
  if (ret != 0)
  {
    printf("create pthread error !\n");
  }
  else
  {
  }

  int len = 0;
  int temp = 1;
  int inSpeed = 0, outSpeed = 0;
  int looptimes = 10;
  int homeOrRoute = 0;
  char *wificlient = NULL;
  int dns_ok = 1;

  c = uci_alloc_context();
  //   printf("tz wireless 22\n");
  wirelessConfig(c, pWireless);
  //   printf("tz wireless\n");
  networkConfig(c, pNet);
  //   printf("tz net\n");
  initReportConfig(c);

  uci_free_context(c);

  while (1)
  {
    //  printf("tz while\n");
    if (getPidByName("pidof freecwmpd") < 1)
      pReal->tr069state = 4;
    else
      pReal->tr069state = 3;
    if (looptimes++ >= 10)
    {
      looptimes = 0;
      getPortState(pReal->portstate);

      getDeviceSpeed(&pReal->upflow, &pReal->downflow);
      uptime = 86886;
      pReal->cputype = 1;
      getConnectNum(&pReal->connectnum);
    }

    memset(sendData, 0, 1500);

    dns_ok = setnameserver(&(server_addr.sin_addr.s_addr), reportServerIp);
    //  server_addr.sin_addr.s_addr= inet_addr(reportServerIp);
    server_addr.sin_port = htons(atoi(reportServerPort));
    if (debug_mode > 0)
      printf("tz report port %s %s\n", reportServerIp, reportServerPort);

    if (dns_ok == 1)
    {
      if (homeOrRoute % 2 == 0)
      {
        get_gw_ip("eth0.2", wanIpaddr);
        if (registState == 0)
        {
          registState = getRegisterState();
        }
        sprintf(sendData, infomsg, deviceMac, commandkey, deviceMac, deviceType, HARD_VERSION, deviceVer, cpuload, uptime, wanIpaddr, registState);
        if (debug_mode > 0)
          printf("send ok\n%s\n", sendData);
        if (sendto(client_socket_fd, sendData, strlen(sendData), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
        {
          printf("Send File Name Failed:");
          //exit(1);
        }
      }
      else
      {
        memset(strhomeState, 0, 1500);
        GetHomeDevice(strhomeState);
        sprintf(sendData, HomeDeviceState,deviceType, deviceMacFu, strhomeState);
        if (debug_mode > 0)
          printf("send ok\n%s\n", sendData);
        if (sendto(client_socket_fd, sendData, strlen(sendData), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
        {
          printf("Send File Name Failed:");
          //exit(1);
        }
      }
    }
    /* 从服务器接收数据，并写入文件 */

    sleep(20);
    homeOrRoute++;
    //break;
  }

  printf("cucuo \n");
  close(client_socket_fd);
  return 0;
}
