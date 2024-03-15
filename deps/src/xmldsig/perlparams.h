#ifndef __PERLPARAMS_H
#define	__PERLPARAMS_H

#include <map>
#include <vector>
#include <string>
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

typedef std::vector<std::map<std::string, std::string> > ArrayOfHash;
typedef std::vector<std::map<std::string, std::string> >::iterator ArrayOfHashIterator;

class CPerlParams
{
private:
	SV *_in;	// входной хеш
	SV *_out;	// выходной хеш

	CPerlParams() {}

public:
	CPerlParams(SV *in);
	~CPerlParams() { _in = 0; _out = 0; }

	SV *GetOutput() { return _out; }

	const char *GetString(const char *path, const char *def = "");
	int GetInt(const char *path, int def = 0);
	const char *operator[](const char *path) { return GetString(path); }

	void SetString(const char *name, const char *val);
	void SetString(const char *name, std::string val) { SetString(name, val.c_str()); }
	void SetInt(const char *name, int val);

	void SetArray(const char *name, ArrayOfHash &ar);
	void GetArray(const char *name, ArrayOfHash &ar);

    void SetHash(const char *name, std::map<std::string, std::string> &ar);
    void GetHash(const char *name, std::map<std::string, std::string> &ar);

    void SetVector(const char *name, std::vector<std::string> &vec);
    void GetVector(const char *path, std::vector<std::string> &vec);
};

#endif
