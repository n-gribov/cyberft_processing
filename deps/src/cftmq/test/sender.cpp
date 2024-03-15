#include "stompc.h"

int main(void)
{
    stomp::connection c;

    if(c.connect("127.0.0.1:40090"))
    {
        if(c.login("root",""))
        {
            for(int i=0;i<10;i++)
            {
                char buf[256]; int n=sprintf(buf,"Hello world %i",i);

//                c.send(buf,"test");

                if(c.send(std::string(buf,n),"test"))
                    printf("%s - ok\n",buf);
                else
                    printf("%s - fail\n",buf);

            }

            c.logout();
        }
    }

    return 0;
}
