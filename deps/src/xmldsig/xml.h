#ifndef __XML_H
#define __XML_H

#include <map>
#include <string>
#include <xmlsec/xmldsig.h>

using namespace std;

typedef bool (*CallbackType)(const string &fingerprint, string &cert, string &SD, string &AP, string &OP);


namespace xml
{
    bool init();
    void done();

    bool verify(const string &msg, const string &xsd_filename, const string &cert, const string &sigpath, map<string, string> &xmlns);
    bool sign(const string &in, string &out, const string &key, const string &cert, const string &pwd, const string &sigpath, map<string, string> &xmlns);
    bool encrypt(const string &msg, vector<string> &cert, const string &sigpath, map<string, string> &xmlns, const string &cipher, string &out);
    bool decrypt(const string &in, const string &key, const string &pwd, const string &sigpath, map<string, string> &xmlns, string &out);

    string getErrors();
    void clearErrors();
}

#endif

