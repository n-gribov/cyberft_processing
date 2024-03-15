#include <stdio.h>
#include <kchashdb.h>
#include <unistd.h>
#include <stdlib.h>

static const char db_name[]="bm_stat.db";

struct record_t
{
    long long int snd;

    long long int rcv;

    long long int ack;

    record_t(void):snd(0),rcv(0),ack(0) {}
};

int main(void)
{
    using namespace kyotocabinet;

    TreeDB db;

    if(db.open(db_name,BasicDB::OWRITER|BasicDB::OCREATE))
    {
        char buf[512];

        while(fgets(buf,sizeof(buf),stdin))
        {
            char* p=strstr(buf,"]: ");

            if(p)
            {
                p+=3;

                int type=0;

                if(!strncmp(p,"snd ",4))
                    type=1;
                else if(!strncmp(p,"rcv ",4))
                    type=2;
                else if(!strncmp(p,"ack ",4))
                    type=3;

                p+=4;

                char* p2=strchr(p,' ');

                if(p2)
                {
                    *p2=0; p2++;

                    char* endptr=NULL;

                    long long int ms=strtoll(p2,&endptr,10);

                    record_t rec;

                    int nn=strlen(p);

                    if(db.get(p,nn,(char*)&rec,sizeof(rec))!=sizeof(rec))
                        memset((char*)&rec,0,sizeof(rec));

                    switch(type)
                    {
                    case 1: rec.snd=ms; break;
                    case 2: rec.rcv=ms; break;
                    case 3: rec.ack=ms; break;
                    }

                    db.set(p,nn,(char*)&rec,sizeof(rec));
                }
            }
        }

        int tmax=0; int tmin=0;
        int tmax_ack=0; int tmin_ack=0;

        DB::Cursor* cur=db.cursor();

        if(cur)
        {
            cur->jump();

            std::string key,value;

            while(cur->get(&key,&value,true))
            {
                record_t* rec=(record_t*)value.c_str();

                int t=rec->rcv-rec->snd;

                int t2=rec->ack-rec->snd;

                if(!tmax || tmax<t) tmax=t;

                if(!tmin || tmin>t) tmin=t;

                if(!tmax_ack || tmax_ack<t2) tmax_ack=t2;

                if(!tmin_ack || tmin_ack>t2) tmin_ack=t2;

                printf("%s;%lli;%lli;%lli\n",key.c_str(),rec->snd,rec->rcv,rec->ack);
            }

            delete cur;
        }


        db.close();

        unlink(db_name);

//        printf("tmin_rcv=%i, tmax_rcv=%i, tmin_ack=%i, tmax_ack=%i\n",tmin,tmax,tmin_ack,tmax_ack);
    }

    return 0;
}
