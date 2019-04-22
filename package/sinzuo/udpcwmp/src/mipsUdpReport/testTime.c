#include<stdio.h>
#include<string.h>
#include<time.h>
int main( void )
{
    struct tm *newtime;
    char tmpbuf[128];
    time_t lt1;
   
    time( &lt1 );
    newtime=localtime(&lt1);
   
    strftime( tmpbuf, 128, "Today is %d, the %d day of %B in the year %Y.\n", newtime);
    printf(tmpbuf);

    printf("jiangyibo %d\n",newtime->tm_wday);

    return 0;
}