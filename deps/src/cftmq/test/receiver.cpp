#include "stompc.h"

int main(void)
{
    stomp::connection c;

    if(c.connect("127.0.0.1:40090"))
    {
        if(c.login("root","") && c.subscribe("test"))
        {
            stomp::frame f;
            
            while(c.recv(f))
            {
                printf("%s\n",f.data.c_str());

                if(!c.ack(f.hdrs["message-id"]))
                    break;
            }

            c.logout();
        }
    }

    return 0;
}
