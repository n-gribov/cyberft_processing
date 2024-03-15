#include "persist.h"
#include <stdio.h>

int main(int argc,char** argv)
{
    persist::storage s;

    if(s.open("test.kch","TreeDB",5,false))
    {
        persist::queue q;

        if(s.get_queue_by_name("test1",q))
        {
            q.push_front("111");
            q.push_front("222");

            printf("%i\n",q.size());
            q.clear();
            printf("%i\n",q.size());

            q.push_front("333");
            q.push_front("444");

        }


/*
        for(int idx=0;idx<1;idx++)
        {
            if(s.get_queue_by_index(idx,q))
            {
                printf("[%i]\n",idx);

                for(int i=0;i<7;i++)
                {
                    char buf[256]; int n=sprintf(buf,"%ivalue%i",idx,i);

                    bool rc=q.push_front(std::string(buf,n));

                    printf("%i: %s\n",i,rc?"true":"false");
                }
            }
        }
*/

        for(int idx=0;idx<5;idx++)
        {
            if(s.get_queue_by_index(idx,q))
            {
                printf("[%i]\n",idx);
                std::string s;
                while(q.pop_back(s))
                    printf("'%s'\n",s.c_str());
            }
        }

        s.close(true);
    }

    return 0;
}
