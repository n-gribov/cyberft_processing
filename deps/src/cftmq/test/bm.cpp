#include "stompc.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>

int max_childs=1000;

int main(void)
{
    setsid();

    for(int i=0;i<max_childs;i++)
    {
        pid_t pid=fork();

        if(pid==(pid_t)-1)
            perror("fork");
        else if(!pid)
        {
            stomp::connection c;

            if(c.connect("127.0.0.1:40090"))
            {
                char dest[64]; sprintf(dest,"%.12i",i);

                if(c.login("root","") && c.subscribe(dest))
                {
                    stomp::frame f;

                    while(c.recv(f))
                    {
//                        printf("%s\n",f.data.c_str());

                        if(!c.ack(f.hdrs["message-id"]))
                            break;
                    }

                    c.logout();
                }
            }

            exit(0);
        }
    }


    stomp::connection c;

    if(c.connect("127.0.0.1:40090"))
    {
        if(c.login("root",""))
        {
            std::string s; s.resize(1024,'0');

            for(int i=0;i<1000000;i++)
            {
                char dest[64]; sprintf(dest,"%.12i",i%max_childs);
                char buf[256]; int n=sprintf(buf,"Hello world %i",i);
                c.send(buf,dest);
//                c.send(s,dest);
            }

            c.logout();
        }
    }

    signal(SIGTERM,SIG_IGN);

    kill(0,SIGTERM);

    return 0;
}
