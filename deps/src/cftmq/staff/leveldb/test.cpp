#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include <stdio.h>


int main(void)
{
    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing=true;
    leveldb::Status status=leveldb::DB::Open(options,"testdb",&db);

    if(!status.ok())
        printf("err %s\n",status.ToString().c_str());
    else
    {
        {
/*
            leveldb::WriteBatch batch;

            for(int i=0;i<1000000;i++)
                { char buf[32]; int n=sprintf(buf,"%i",i); batch.Put(std::string(buf,n),std::string(buf,n)); }

            leveldb::WriteOptions write_options;
            write_options.sync=true;

            status=db->Write(write_options,&batch);
            if(!status.ok())
                printf("err %s\n",status.ToString().c_str());
*/
/*
            leveldb::WriteOptions write_options;
            write_options.sync=false;

            for(int i=0;i<1000000;i++)
                { char buf[32]; int n=sprintf(buf,"%i",i); db->Put(write_options,std::string(buf,n),std::string(buf,n)); }
*/
        }

        std::string s;
        db->Get(leveldb::ReadOptions(),"756234",&s);
        printf("%s\n",s.c_str());

        delete db;
    }

    return 0;
}
