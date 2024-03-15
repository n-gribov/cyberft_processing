#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "stompc.h"

enum { max_chunks=10000, max_len=2000 * 1024 * 1024 };

namespace cfg
{
    int timeout=5;

    std::string addr="127.0.0.1:40090";
    std::string username="admin";
    std::string passcode="";
    std::string queue="test";

    std::string workdir="./";
}

class alrm
{
public:
    alrm(int n) { alarm(n); }
    ~alrm(void) { alarm(0); }
};

class file
{
public:
    FILE* fp;

    file(FILE* _fp):fp(_fp) {}
    ~file(void) { close(); }

    void close(void) { if(fp) { fclose(fp); fp=NULL; } }
};

struct chunk_info
{
    std::string seq;
    int id;
    int total;
    int offset;
    int size;
    int size_total;
    std::string dgst;
    std::string data;

    bool init(const std::string& seq_id,const std::string& chunk_id,const std::string& chunk_range,const std::string& chunk_dgst);
};

static void __sig_handler(int n) { }

stomp::connection con;

static int login(void)
{
    alrm a(cfg::timeout);

    if(!con.connect(cfg::addr))
        { fprintf(stderr,"** unable to establish connection\n"); return -1; }

    if(!con.login(cfg::username,cfg::passcode))
        { fprintf(stderr,"** access denied\n"); return -2; }

    if(!con.subscribe(cfg::queue))
        { fprintf(stderr,"** unable to subscribe\n"); return -3; }

    return 0;
}

static int logout(void)
{
    alrm a(cfg::timeout);

    con.logout();

    con.close();

    return 0;
}

bool chunk_info::init(const std::string& seq_id,const std::string& chunk_id,const std::string& chunk_range,const std::string& chunk_dgst)
{
// seq-id:12345
// chunk-id:1/10
// chunk-range:0-10/1000000
// chunk-dgst:14e1a1785cc9716a6b8ff8161e394337

    seq=seq_id;

    std::string::size_type p1=chunk_id.find('/');
    if(p1!=std::string::npos)
        { id=atoi(chunk_id.substr(0,p1).c_str()); total=atoi(chunk_id.substr(p1+1).c_str()); }

    p1=chunk_range.find('-');
    if(p1!=std::string::npos)
    {
        offset=atoi(chunk_range.substr(0,p1++).c_str());
        std::string::size_type p2=chunk_range.find('/',p1);
        if(p2!=std::string::npos)
            { size=atoi(chunk_range.substr(p1,p2-p1).c_str())-offset+1; size_total=atoi(chunk_range.substr(p2+1).c_str()); }
    }

    dgst=chunk_dgst;

/*
    fprintf(stderr,"      seq: %s\n",seq.c_str());
    fprintf(stderr,"      id: %i\n",id);
    fprintf(stderr,"      total: %i\n",total);
    fprintf(stderr,"      offset: %i\n",offset);
    fprintf(stderr,"      size: %i\n",size);
    fprintf(stderr,"      size_total: %i\n",size_total);
    fprintf(stderr,"      dgst: %s\n",dgst.c_str());
*/

    return true;
}

static int onchunk(chunk_info& c)
{
    if(c.seq.empty() || c.id<1 || c.id>c.total || c.total<1 || c.total>max_chunks || c.offset<0 || c.size<1 || c.size_total<1 ||
        c.offset+c.size>c.size_total || c.size_total>max_len || c.data.size()!=c.size)
            return -1;

    std::string dpath=cfg::workdir+c.seq+".part~";  // файл для временного хранения данных серии
    std::string spath=cfg::workdir+c.seq+".stat~";  // файл для временного хранения информации о принятых фрагментах

    file dfp(fopen(dpath.c_str(),"r+"));

    if(!dfp.fp)    // первый фрагмент, файла пока нет
    {
        dfp.fp=fopen(dpath.c_str(),"w+");

        if(dfp.fp) // создаем новый временный файл и раздвигаем его
        {
            fseek(dfp.fp,c.size_total-1,SEEK_SET);
            fputc(0,dfp.fp); fflush(dfp.fp);
        }
    }else
    {
        fseek(dfp.fp,0,SEEK_END);
        if(c.size_total!=ftell(dfp.fp)) // максимальная длина во всех фрагментах не должна меняться
            return -1;
    }

    if(!dfp.fp)
        return -2;

    // текущее количество успешно принятых фрагментов (что б понять когда весь файл готов)
    u_int32_t chunks_received=0;

    // создаем файл для хранения текущего статуса загрузки
    // статусный файл содержит в себе максимальное кол-во фрагментов (из первого фрагмента),
    // количество успешно принятых и битовую маску принятых фрагментов.
    // начинается файл с символа с кодом 0x02 (STX — start of text), заканчивается 0x04 (EOT — end of transmission)
    // общий размер файла в байтах = STX + chunks_total + chunks + bitmap + EOT


    file sfp(fopen(spath.c_str(),"r+"));
    if(!sfp.fp)
    {
        sfp.fp=fopen(spath.c_str(),"w+");

        if(sfp.fp)
        {
            // вычисляем кличетво 32-х битных юнитов для хранения битовой маски принятых фрагментов (округляем в большую сторону)
            int units=c.total/32;
            if(c.total%32)
                units++;

            // инициализируем новый файл
            fputc(0x02,sfp.fp);

            u_int32_t nn=c.total; fwrite((char*)&nn,sizeof(nn),1,sfp.fp); nn=0;

            for(int i=0;i<units+1;i++)
                fwrite((char*)&nn,sizeof(nn),1,sfp.fp);

            fputc(0x04,sfp.fp);
            fflush(sfp.fp);
        }
    }else
    {
        // проверяем файл на валидность и убеждаемся что общее количество фрагментов не изменилось
        if(fgetc(sfp.fp)!=0x02)
            return -3;

        u_int32_t nn=0;
        if(fread((char*)&nn,1,sizeof(nn),sfp.fp)!=sizeof(nn) || nn!=c.total)
            return -3;

        if(fread((char*)&chunks_received,1,sizeof(chunks_received),sfp.fp)!=sizeof(chunks_received))
            return -3;
    }

    if(!sfp.fp)
        return -3;

    // битовая маска
    u_int32_t bitmap=0; int bitmap_offset=0;

    // смотрим есть ли у нас уже такой фрагмент
    {

        // сдвигаемся к нужному юниту (9 это смещение битовой маски от начала)
        if(fseek(sfp.fp,(c.id-1)/32+9,SEEK_SET) || fread((char*)&bitmap,1,sizeof(bitmap),sfp.fp)!=sizeof(bitmap))
            return -3;

        if((bitmap<<=(c.id-1)%32)&0x80000000) // фрагмент уже есть, пропускаем
        {
            printf("** %s/%i alredy is exist\n",c.seq.c_str(),c.id);

            return 0;
        }else           // фрагмента нет, взводим бит
            bitmap|=0x80000000>>(c.id-1)%32;

        // сохраняем позицию для записи битовой маски
        bitmap_offset=ftell(sfp.fp)-4;
    }

    // пишем фрагмент
    {
        if(fseek(dfp.fp,c.offset,SEEK_SET))
            return -4;

        int l=0;

        while(l<c.data.length())
        {
            int n=fwrite(c.data.c_str()+l,1,c.data.length()-l,dfp.fp);

            if(n<=0)
                break;

            l+=n;
        }

        if(l!=c.data.length() || fflush(dfp.fp))  // ошибка записи
            return -4;
    }

    chunks_received++;

    if(fseek(sfp.fp,5,SEEK_SET) || fwrite((char*)&chunks_received,1,sizeof(chunks_received),sfp.fp)!=sizeof(chunks_received) ||
        fseek(sfp.fp,bitmap_offset,SEEK_SET) || fwrite((char*)&bitmap,1,sizeof(bitmap),sfp.fp)!=sizeof(bitmap) || fflush(sfp.fp))
            { fprintf(stderr,"** unable to save stat of %s/%i\n",c.seq.c_str(),c.id); return -5; }

    if(chunks_received==c.total)                // файл готов
    {
        sfp.close(); dfp.close();

        unlink(spath.c_str());
        rename(dpath.c_str(),(cfg::workdir+c.seq).c_str());
        return 1;
    }

    return 0;
}

int main(int argc,char** argv)
{
    struct sigaction sig;
    sig.sa_handler=__sig_handler;
    sigfillset(&sig.sa_mask);
    sig.sa_flags=0;

    sigaction(SIGALRM,&sig,NULL);
    sigaction(SIGINT,&sig,NULL);
    sigaction(SIGQUIT,&sig,NULL);
    sigaction(SIGTERM,&sig,NULL);

    sig.sa_handler=SIG_IGN;
    sigaction(SIGPIPE,&sig,NULL);
    sigaction(SIGHUP,&sig,NULL);

    fprintf(stderr,"** trying to establish connection...\n");

    if(!login())
    {
        fprintf(stderr,"** connected, waiting...\n");

        stomp::frame f;

        while(con.recv(f))
        {
            std::string& msg_id=f.hdrs["message-id"];

            printf("** msg: %s\n",msg_id.c_str());

            std::string seq_id=f.hdrs["seq-id"];

            if(seq_id.empty())
                seq_id=f.hdrs["doc_id"];

            chunk_info c;
            if(c.init(seq_id,f.hdrs["chunk-id"],f.hdrs["chunk-range"],f.hdrs["chunk-dgst"]))
            {
                c.data.swap(f.data);

                int rc=onchunk(c);

                if(rc<0)
                    printf("** msg %s is rejected (%i)\n",msg_id.c_str(),rc);
                else if(rc>0)
                    printf("** msg %s is ready\n",msg_id.c_str());
            }

            {
                alrm a(cfg::timeout);

                if(!con.ack(msg_id))
                    break;
            }
        }

        fprintf(stderr,"** disconnecting...\n");

        logout();
    }

    fprintf(stderr,"** bye.\n");


    return 0;
}
