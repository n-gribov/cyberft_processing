#include "stompc.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <uuid/uuid.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <sys/wait.h>

static const char tmpl[]=
"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
"<Document xmlns=\"http://cyberft.ru/xsd/cftdoc.01\">"
"<Header>"
   "<DocId>%s</DocId>"
   "<DocDate>2016-05-12T10:53:31+03:00</DocDate>"
   "<SenderId>%s</SenderId>"
   "<ReceiverId>%s</ReceiverId>"
   "<DocType>MT999</DocType>"
   "<DocDetails>"
      "<PaymentRegisterInfo sum=\"0\" count=\"1\"/>"
   "</DocDetails>"
   "<SignatureContainer>"
      "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
         "<SignedInfo>"
            "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
            "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
            "<Reference URI=\"\">"
               "<Transforms>"
                  "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                  "<Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\">"
                     "<XPath xmlns:doc=\"http://cyberft.ru/xsd/cftdoc.01\">not(ancestor-or-self::doc:SignatureContainer or ancestor-or-self::doc:TraceList)</XPath>"
                  "</Transform>"
               "</Transforms>"
               "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
               "<DigestValue>HtwVwz8jbyUedubxkTlZGMMl2Ro=</DigestValue>"
            "</Reference>"
         "</SignedInfo>"
         "<SignatureValue>hegcpHQN8stiMR7BgASug0dkxCXqsHcmGJpBSi1mhVBnbLG8cI4FzBGbK3ORJBlDJefK2uehzpItO5hSRcnGp34PVFMeeiBLb6qqrWpdXN+QxCxWRAqxK1g0eiE3tj26TrhXGYC+P3R3SOO0pHp+zIkdOIbX9nKNeY63T4zYpBGP4ghgXne5k1ponUP8pcnn1R3IsM7Mg6egjZEdg3Png0H/982zgc4FJHy0by1YyhIh7x29TaKDvwPQuUAI1JqNascDv2G6aSi/wRg/cfNNHiYjpV0nboO0tTlKzIaEJmPtug6CMowfYRGiZMyCkKdAJu3CIecpTuNQBAhGxOM0IA==</SignatureValue>"
         "<KeyInfo>"
            "<KeyName>%s</KeyName>"
         "</KeyInfo>"
      "</Signature>"
   "</SignatureContainer>"
"</Header>"
"<Body encoding=\"base64\" mimeType=\"application/text\">"
   "<RawData xmlns=\"http://cyberft.ru/xsd/cftdata.01\">AXsxOkYwMVNJTUtJTjFAVEVTVDAwMDAwMDAwMDB9ezI6STk5OVNJTUtJTjFAVEVTVE59ezQ6CjoyMDp0eWh0eQ0KOjc5OnR5aHR5aHl0DQotfQMNCg==</RawData>"
"</Body>"
"</Document>";

struct link_t
{
    const char* from;
    const char* key;
    const char* to;
};

static const link_t links[]=
{
    {"DANIXXL@ENKO", "BBD1E681688FA5B75DC5425074DCECAD731A63A9", "TESTXXX@X001"},
    {"EGORRUM@AXXX", "076FBA619E732E9CC97BDEE61E77372778A28DD4", "VELERUM@A001"},
    {"KOVALKO@XDEV", "E9D1B49CE737E6387EBDE172BAC580609376AC78", "TESTRUM@A763"},
    {"SIMKIN1@BEST", "F264E6878C7D1E17ED4CEA663C1BB00EE337FA2A", "TESTPDV@X001"},
    {"TESTDEP@A001", "F7F8756F0C9803B7CD2D9BE943FB86CCA7B7ABFD", "TESTDEP@B001"},
    {"TESTDEP@B001", "40864FE5CEE86D3EB6EC31A76341F9C7C7EFB689", "TESTDEP@A001"},
    {"TESTPDV@X001", "9B7B34AF26D40555FC48D1CE42AEB8046BB96689", "SIMKIN1@BEST"},
    {"TESTRUM@A763", "97F193BBD0F2042A0727A6BCDA16E1A12619BAC0", "KOVALKO@XDEV"},
    {"VELERUM@A001", "4A9BB9B32BBBC6F15364FDD83D18A36C5492B608", "EGORRUM@AXXX"},
    {"TESTXXX@X001", "D0357B3B4D7AE4636EB9D98E72A8E2C6F0772D3D", "DANIXXL@ENKO"}
};

unsigned long long now(void)
{
    struct timeval tv;

    gettimeofday(&tv,NULL);

    return tv.tv_sec*1000+tv.tv_usec/1000;
}

int main(void)
{
    unsigned long long t0=now();

    openlog("cftbm",LOG_PID,LOG_LOCAL0);

    int max_childs=sizeof(links)/sizeof(*links);

    setsid();

    for(int i=0;i<max_childs;i++)
    {
        pid_t pid=fork();

        if(pid==(pid_t)-1)
            perror("fork");
        else if(!pid)
        {
            stomp::connection c;

            if(c.connect("192.168.57.72:40090") && c.login(links[i].from,links[i].from) && c.subscribe(links[i].from))
            {
                stomp::frame f;

                while(c.recv(f))
                {
                    if(f.hdrs["doc_type"]=="CFTAck")
                    {
                        std::string ref_doc_id=f.hdrs["ref_doc_id"];

                        if(ref_doc_id.empty())
                        {
                            const char* p1=strstr(f.data.c_str(),"<RefDocId>");
                            if(p1)
                            {
                                p1+=10;

                                const char* p2=strstr(p1,"</RefDocId>");

                                if(p2)
                                    ref_doc_id.assign(p1,p2-p1);
                            }
                        }

                        syslog(LOG_INFO,"ack %s %llu",ref_doc_id.c_str(),now()-t0);
                    }else if(f.hdrs["doc_type"]=="MT999")
                        syslog(LOG_INFO,"rcv %s %llu",f.hdrs["doc_id"].c_str(),now()-t0);

                    if(!c.ack(f.hdrs["message-id"]))
                        break;
                }

                c.logout();
            }

            exit(0);
        }
    }

    pid_t pids[64];

    for(int i=0;i<max_childs;i++)
    {
        pid_t pid=fork();

        pids[i]=pid;

        if(pid==(pid_t)-1)
            perror("fork");
        else if(!pid)
        {
            stomp::connection c;

            if(c.connect("192.168.57.72:40090") && c.login(links[0].from,links[0].from))
            {
                for(int j=0;j<1000;j++)
                {
                    char uuid[64];

                    uuid_t _uuid; uuid_generate(_uuid); uuid_unparse_lower(_uuid,uuid);

                    char buf[4096]; int n=sprintf(buf,tmpl,uuid,links[0].from,links[0].to,links[0].key);

                    c.send(buf,"INPUT");

                    syslog(LOG_INFO,"snd %s %llu",uuid,now()-t0);

                    usleep(140000);
                }

                c.logout();
            }

            exit(0);
        }
    }

    int childs_left=max_childs;

    while(childs_left>0)
    {
        pid_t pid=wait(NULL);

        for(int i=0;i<max_childs;i++)
            if(pid==pids[i])
                { childs_left--; break; }
    }

    printf("wait for CTRL+C\n");

    pause();

    signal(SIGTERM,SIG_IGN);

    kill(0,SIGTERM);

    return 0;
}
