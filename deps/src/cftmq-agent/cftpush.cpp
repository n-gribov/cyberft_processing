#include "stompc.h"

enum { max_num=50 };

int main(void)
{
    stomp::frame f("SEND");
    f.data.resize(10 * 1024 * 1024,'$');
    f.hdrs["destination"]="test";
    f.hdrs["seq-id"]="12345";

    stomp::connection c;

    if(c.connect("127.0.0.1:40090"))
    {
        if(c.login("admin",""))
        {
            for(int i=1;i<=max_num;i++)
            {
                char buf[256]; int n=sprintf(buf,"%i/%i",i,max_num);

                f.hdrs["chunk-id"]=buf;
printf("chunk-id: %s\n",buf);

                int offset=(i-1)*f.data.size();

                n=sprintf(buf,"%i-%i/%i",offset,(int)(offset+f.data.size())-1,(int)(f.data.size()*max_num));

                f.hdrs["chunk-range"]=buf;
printf("chunk-range: %s\n",buf);

                if(!c.send(f))
                    break;
            }

            c.logout();
        }
    }

    return 0;
}
