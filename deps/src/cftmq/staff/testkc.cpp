#include <kchashdb.h>
#include <sstream>


int main(void)
{
    using namespace kyotocabinet;

    TreeDB db;

    if(db.open("test.kch",TreeDB::OWRITER|TreeDB::OCREATE))
    {
/*
        for(int i=0;i<1000000;i++)
        {
            db.set(std::string((char*)&i,sizeof(i)),"test");
        }
*/


        int key=500000;

        std::stringstream s;

        for(int i=0;i<10000000;i++)
            s<<"test";
        
        db.append(std::string((char*)&key,sizeof(key)),s.str());

/*
        for(int i=0;i<100000;i++)
            db.append(std::string((char*)&key,sizeof(key)),"test");
            
//real    0m3.566s
//user    0m3.564s
//sys     0m0.000s
*/

        db.close();
    }

    return 0;
}
