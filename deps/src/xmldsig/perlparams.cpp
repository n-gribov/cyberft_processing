#include "perlparams.h"

CPerlParams::CPerlParams(SV *in) : _in(in)
{ 
	if (!_in && SvTYPE(SvRV(_in)) != SVt_PVHV)	// ожидаем на входе ссылку на хеш
		_in = 0;
	_out = sv_2mortal((SV*) newHV());		// удалится в Perl программе потом сам
}

const char *CPerlParams::GetString(const char *path, const char *def)
{
	const char *result = def;
	SV **par, *my_perl_in = _in;

	if (_in && path) {
		const char *param = path;
		int param_len = strlen(param);
		if (*param && hv_exists((HV *) SvRV(my_perl_in), param, param_len)) {
			par = hv_fetch((HV *) SvRV(my_perl_in), param, param_len, 0);
			result = SvPV(*par, PL_na);
		}
	}
	return result;
}

int CPerlParams::GetInt(const char *path, int def)
{
	int result = def;
	SV** par;

	if (_in && path) {
		int path_len = strlen(path);
		if (hv_exists((HV *) SvRV(_in), path, path_len)) {
			par = hv_fetch((HV *) SvRV(_in), path, path_len, 0);
			result = atoi(SvPV(*par, PL_na));
		}
	}
	return result;
}

void CPerlParams::SetString(const char *name, const char *val)
{
	if (_out)
		hv_store((HV *) _out, name, strlen(name), newSVpv(val, 0), 0);
}

void CPerlParams::SetInt(const char *name, int val)
{
	if (_out)
		hv_store((HV *) _out, name, strlen(name), newSViv(val), 0);
}

void CPerlParams::SetArray(const char *name, ArrayOfHash &in_array)
{
	if (!_out || in_array.empty()) return;

	AV* rows = (AV*) sv_2mortal((SV*) newAV());	// новый массив
	for (unsigned int i=0; i<in_array.size(); i++) {
		SV* row = sv_2mortal((SV*) newHV());	// новый хэш

		std::map<std::string, std::string> a = in_array[i];
		for (std::map<std::string, std::string>::iterator it = a.begin(); it != a.end(); it++) {
			// добавить строку в хэш
			hv_store((HV*) row, it->first.c_str(), it->first.size(), newSVpv(it->second.c_str(), it->second.size()), 0);
		}
		av_push(rows, newRV(row));	// добавить строку в массив
	}
	hv_store((HV *) _out, name, strlen(name), newRV((SV *) rows), 0);	// добавить ссылку на массив в результат
}

void CPerlParams::GetArray(const char *path, ArrayOfHash &out_array)
{
	if (_in && path) {
		int path_len = strlen(path);
		if (hv_exists((HV *) SvRV(_in), path, path_len)) {
			SV** par = hv_fetch((HV *) SvRV(_in), path, path_len, 0);
			if (SvTYPE(SvRV(*par)) == SVt_PVAV) {
				AV *arr = (AV*) SvRV(*par);	// ссылка на массив
				I32 upper = av_len(arr);
				for (I32 i=0; i<=upper; i++) {
					SV **val = av_fetch(arr, i, 0);
					if (SvTYPE(SvRV(*val)) == SVt_PVHV) {
						HV *hash = (HV*) SvRV(*val); 	// ссылка на хеш
						HE *pHE = NULL;
						if (hv_iterinit(hash) > 0) {
							std::map<std::string, std::string> m;
							while ((pHE=hv_iternext(hash))) {
								I32 len = 0;
								m[hv_iterkey(pHE, &len)] = SvPV(hv_iterval(hash, pHE), PL_na);
							}
							out_array.push_back(m);
						}
					}
				}
			}
		}
	}
}

void CPerlParams::SetHash(const char *name, std::map<std::string, std::string> &h)
{
    if (!_out || h.empty()) return;
    SV* row = sv_2mortal((SV*) newHV());

    for (std::map<std::string, std::string>::iterator it = h.begin(); it != h.end(); it++) {
        hv_store((HV*) row, it->first.data(), it->first.size(), newSVpv(it->second.data(), it->second.size()), 0);
    }
    hv_store((HV *) _out, name, strlen(name), newRV((SV *) row), 0);
}

void CPerlParams::GetHash(const char *path, std::map<std::string, std::string> &out_array)
{
    out_array.clear();
    if (_in && path) {
        int path_len = strlen(path);
        if (hv_exists((HV *) SvRV(_in), path, path_len)) {
            SV** par = hv_fetch((HV *) SvRV(_in), path, path_len, 0);
            if (SvTYPE(SvRV(*par)) == SVt_PVHV) {
                HV *hash = (HV*) SvRV(*par);
                HE *pHE = NULL;
                if (hv_iterinit(hash) > 0) {
                    while ((pHE=hv_iternext(hash))) {
                        I32 len = 0;
                        out_array[hv_iterkey(pHE, &len)] = SvPV(hv_iterval(hash, pHE), PL_na);
                    }
                }
            }
        }
    }
}

void CPerlParams::SetVector(const char *name, std::vector<std::string> &vec)
{
	if (!_out || vec.empty()) return;

	AV* rows = (AV*) sv_2mortal((SV*) newAV());	// новый массив
	for (unsigned int i=0; i<vec.size(); i++) {
		av_push(rows, newSVpv(vec[i].c_str(), vec[i].size()));	// добавить строку в массив
	}
	hv_store((HV *) _out, name, strlen(name), newRV((SV *) rows), 0);	// добавить ссылку на массив в результат
}

void CPerlParams::GetVector(const char *path, std::vector<std::string> &vec)
{
    vec.clear();

    if (_in && *path) {
        int path_len = strlen(path);
        if (hv_exists((HV *) SvRV(_in), path, path_len)) {
            SV** par = hv_fetch((HV *) SvRV(_in), path, path_len, 0);
            if (SvTYPE(SvRV(*par)) == SVt_PVAV) {
				AV *arr = (AV*) SvRV(*par);	// ссылка на массив
				I32 upper = av_len(arr);
				for (I32 i=0; i<=upper; i++) {
					SV **par = av_fetch(arr, i, 0);
                    vec.push_back((const char *) SvPV(*par, PL_na));
                }
            }
        }
    }
}

