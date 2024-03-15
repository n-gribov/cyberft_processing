#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <termios.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "stompc.h"

namespace cfg
{
    int timeout=5;

    int chunk_size=0;

    std::string addr;
    std::string username;
    std::string passcode;

    std::string file1;
    std::string file2;

    std::string filename;

    bool send=false;

    bool verb=false;

    bool resume=false;
}

class alrm
{
public:
    alrm(int n) { alarm(n); }
    ~alrm(void) { alarm(0); }
};

static void __sig_handler(int n) { }

stomp::connection con;

static int login(void)
{
    alrm a(cfg::timeout);

    if(!con.connect(cfg::addr))
        { fprintf(stderr,"unable to establish connection\n"); return -1; }

    if(!con.login(cfg::username,cfg::passcode))
        { fprintf(stderr,"access denied\n"); return -2; }

    return 0;
}

static int logout(void)
{
    alrm a(cfg::timeout);

    con.logout();

    con.close();

    return 0;
}


static int push_file(void)
{
    int fd=open(cfg::file1.c_str(),O_RDONLY);

    if(fd==-1)
        { fprintf(stderr,"file '%s' is not found\n",cfg::file1.c_str()); return -1; }

    off_t length=lseek(fd,0,SEEK_END); lseek(fd,0,SEEK_SET);

    if(cfg::verb)
        fprintf(stderr,"filename: %s, length:%lu, chunk size: %i\n",cfg::file1.c_str(),length,cfg::chunk_size);

    int max_num=length/cfg::chunk_size+1;

    int offset=0;

    std::string stat_filename=cfg::file1+".stat~";

    if(cfg::resume)
    {
        FILE* fp=fopen(stat_filename.c_str(),"r");

        if(fp)
            { fscanf(fp,"%i",&offset); fclose(fp); unlink(stat_filename.c_str()); }

        if(offset<0 || offset>=(int)length || offset%cfg::chunk_size)
            offset=0;

        lseek(fd,offset,SEEK_SET);

        length-=offset;
    }

    for(int i=offset/cfg::chunk_size;i<max_num;i++)
    {
        int size=length>cfg::chunk_size?cfg::chunk_size:length;

        if(size<1)
            continue;

        if(cfg::verb)
            fprintf(stderr,"chunk %i, offset=%i, size=%i\n",i,offset,size);

        std::string s; s.reserve(size);

        char buf[1024];

        int l=size;

        while(l>0)
        {
            ssize_t n=read(fd,buf,l>sizeof(buf)?sizeof(buf):l);

            if(n==0 || n==(ssize_t)-1)
                break;

            s.append(buf,n);

            l-=n;
        }

        if(l!=0)
            { fprintf(stderr,"unable to read chunk %i\n",i); close(fd); return -1; }

        int n=sprintf(buf,"%i-%i",offset,(int)(offset+size)-1);

        bool is_ok=false;

        {
            alrm a(cfg::timeout);

            stomp::frame f("PUT");
            f.hdrs["seq-id"]=cfg::file2;
            f.hdrs["range"]=buf;
            f.hdrs["receipt"]="123456";
            f.data.swap(s);

            if(con.send(f) && con.recv(f) && f.command=="RECEIPT")
                { is_ok=true; if(cfg::filename.empty()) cfg::filename=f.hdrs["filename"]; }
        }

        if(!is_ok)
        {
            fprintf(stderr,"unable to send chunk %i\n",i);
            close(fd);

            if(cfg::resume)
            {
                FILE* fp=fopen(stat_filename.c_str(),"w");

                if(fp) { fprintf(fp,"%i",offset); fclose(fp); }
            }

            return -1;
        }

        length-=size;
        offset+=size;
    }

    close(fd);

    return 0;
}

static int pull_file(void)
{
    std::string filename=cfg::file2+".part~";

    if(!cfg::resume)
        unlink(filename.c_str());

    int fd=open(filename.c_str(),O_WRONLY|O_CREAT,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

    if(fd==-1)
        { fprintf(stderr,"unable to create file '%s'\n",filename.c_str()); return -1; }

    off_t offset=lseek(fd,0,SEEK_END);

    if(cfg::verb)
        fprintf(stderr,"filename: %s, offset:%lu, chunk size: %i\n",filename.c_str(),offset,cfg::chunk_size);

    for(int i=0;;i++)
    {
        if(cfg::verb)
            fprintf(stderr,"chunk %i, offset=%lu, size=%i\n",i,offset,cfg::chunk_size);

        bool is_ok=false;

        int size=0;

        char buf[256]; int n=sprintf(buf,"%lu-%i",offset,(int)(offset+cfg::chunk_size)-1);

        {
            alrm a(cfg::timeout);

            stomp::frame f("GET");
            f.hdrs["seq-id"]=cfg::file1;
            f.hdrs["range"]=buf;
            f.hdrs["receipt"]="123456";

            if(con.send(f) && con.recv(f) && f.command=="RECEIPT")
            {
                const std::string& ss=f.hdrs["content-length"];

                const std::string& s=f.data;

                if(!ss.empty())
                {
                    size=atoi(ss.c_str());

                    if(size>=0 && size==s.length())
                    {
                        int l=0;

                        while(l<size)
                        {
                            ssize_t n=write(fd,s.c_str()+l,s.length()-l);

                            if(n==0 || n==(ssize_t)-1)
                                break;

                            l+=n;
                        }

                        if(l==size)
                            is_ok=true;
                    }
                }
            }
        }

        if(!is_ok)
            { fprintf(stderr,"unable to recv chunk %i\n",i); close(fd); return -1; }

        if(size<cfg::chunk_size)
        {
            close(fd); fd=-1;

            rename(filename.c_str(),cfg::file2.c_str());

            cfg::filename=cfg::file2;

            break;
        }

        offset+=size;
    }

    if(fd!=-1)
        close(fd);

    return 0;
}


static void parse_url(const std::string& s,std::string& user,std::string& host,std::string& file)
{
    std::string::size_type n=s.find(':');

    if(n==std::string::npos)
        file=s;
    else
    {
        file=s.substr(n+1);

        std::string ss(s.substr(0,n));

        n=ss.find('@');

        if(n==std::string::npos)
            host=ss;
        else
            { user=ss.substr(0,n); host=ss.substr(n+1); }
    }
}

int main(int argc,char** argv)
{
    std::string from,to,port;

    int rc=-1;

    int opt;
    while((opt=getopt(argc,argv,"h?vP:T:C:RU:"))>0)
        switch(opt)
        {
        case 'h':
        case '?':
            fprintf(stderr,"USAGE: ./cftcp [-h] [-P port] [-T timeout] [-C chunk_size] [-U username] [-R] [[user@]host1:]file1 ... [[user@]host2:]file2\n");
            exit(0);
        case 'v': cfg::verb=true; break;
        case 'P': port=optarg; break;
        case 'T': cfg::timeout=atoi(optarg); break;
        case 'C': cfg::chunk_size=atoi(optarg); break;
        case 'R': cfg::resume=true; break;
        case 'U': cfg::username=optarg; break;
        }

    if(argc-optind>0)
        from=argv[optind];
    if(argc-optind>1)
        to=argv[optind+1];

    if(from.empty())
        { fprintf(stderr,"source file is not specified\n"); exit(1); }

    if(from.find(':')!=std::string::npos)
        { parse_url(from,cfg::username,cfg::addr,cfg::file1); cfg::file2=to; }
    else
        { cfg::file1=from; parse_url(to,cfg::username,cfg::addr,cfg::file2); cfg::send=true; }

    if(cfg::addr.empty())
        { fprintf(stderr,"host is not specified\n"); exit(1); }

    if(!port.empty())
        cfg::addr+=':'+port;
    else
        cfg::addr+=":40090";

    if(cfg::timeout<0)
        cfg::timeout=0;

    if(cfg::chunk_size<1)
        cfg::chunk_size=1024;

    if(cfg::file2.empty())
        cfg::file2=cfg::file1;

    {
        struct termios ti_old,ti_new;

        int rc=tcgetattr(fileno(stdin),&ti_old);

        if(!rc)
        {
            ti_new=ti_old;
            ti_new.c_lflag&=~ECHO;
            tcsetattr(fileno(stdin),TCSAFLUSH,&ti_new);

            fprintf(stderr,"passphrase: "); fflush(stderr);
        }

        char buf[256];

        if(fgets(buf,sizeof(buf),stdin))
            { char* p=strpbrk(buf,"\r\n"); if(p) *p=0; cfg::passcode=buf; }


        if(!rc)
            { tcsetattr(fileno(stdin),TCSAFLUSH,&ti_old); printf("\n"); }
    }

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

    fprintf(stderr,"trying to establish connection with '%s' ...\n",cfg::addr.c_str());

    if(cfg::verb)
        fprintf(stderr,"login: %s, timeout: %i\n",cfg::username.c_str(),cfg::timeout);

    if(!login())
    {
        fprintf(stderr,"connected\n");

        if(cfg::send)
            rc=push_file();
        else
            rc=pull_file();

        fprintf(stderr,"disconnecting...\n");

        logout();
    }

    if(!rc && !cfg::filename.empty())
        { fprintf(stderr,"file was %s successfully, filename: '%s'\n",cfg::send?"sent":"received",cfg::filename.c_str()); }
    else
        { fprintf(stderr,"file not %s\n",cfg::send?"sent":"received"); }

    fprintf(stderr,"bye.\n");

    return rc?1:0;
}

