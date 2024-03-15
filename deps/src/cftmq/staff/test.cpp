#include <string>
#include <sstream>



int main(void)
{
/*
    std::stringstream ss;
    
    for(int i=0;i<10000000;i++)
        ss<<'a';

    std::string s=ss.str();

//real    0m0.377s
//user    0m0.360s
//sys     0m0.016s
*/

/*
    std::string s; s.reserve(10000000);
    
    for(int i=0;i<10000000;i++)
        s+='a';

//real    0m0.083s
//user    0m0.080s
//sys     0m0.000s

*/


    std::stringbuf ss;
    
    for(int i=0;i<10000000;i++)
        ss.sputc('a');

    std::string s=ss.str();

//real    0m0.064s
//user    0m0.044s
//sys     0m0.016s


    return 0;
}