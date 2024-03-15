/*
 Signing and verifying XML Signature using xmlsec library
*/

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include "perlparams.h"
#include "xml.h"

enum cmnds {CMD_SIGN, CMD_VERIFY, CMD_ENCRYPT, CMD_DECRYPT};

#define INVOKE_FUNC(type)   dXSARGS; \
    if (items != 1 || SvTYPE(SvRV(ST(0))) != SVt_PVHV) { \
        croak("Args num err. No input hash"); \
        XSRETURN(0); \
        return; \
    } \
    CPerlParams params(ST(0)); \
    callGateway(type, params); \
    ST(0) = newRV_noinc(params.GetOutput()); \
    XSRETURN(1);

void callGateway(cmnds cmd, CPerlParams &params)
{
    bool res = false;
    string out;
    string sigpath = params["sigpath"];
    map<string, string> xmlns;

    xml::clearErrors();
    params.GetHash("xmlns", xmlns);

    if (cmd == CMD_SIGN) {
        if ((res = xml::sign(params["template"], out, params["key"], params["cert"], params["pwd"], sigpath, xmlns)))
            params.SetString("xml", out);
        else
            params.SetString("errmsg", xml::getErrors());
    } else if (cmd == CMD_VERIFY) {
        if (!(res = xml::verify(params["xml"], params["xsd"], params["cert"], sigpath, xmlns)))
            params.SetString("errmsg", xml::getErrors());
    } else if (cmd == CMD_ENCRYPT) {
        vector<string> certs;
        params.GetVector("certs", certs);
        if ((res = xml::encrypt(params["template"], certs, sigpath, xmlns, params["cipher"], out)))
            params.SetString("xml", out);
        else
            params.SetString("errmsg", xml::getErrors());
    } else if (cmd == CMD_DECRYPT) {
        if ((res = xml::decrypt(params["xml"], params["key"], params["pwd"], sigpath, xmlns, out)))
            params.SetString("xml", out);
        else
            params.SetString("errmsg", xml::getErrors());
    }
    params.SetInt("result", !res);
}

XS(XS_sign)
{
    INVOKE_FUNC(CMD_SIGN)
}

XS(XS_verify)
{
    INVOKE_FUNC(CMD_VERIFY)
}

XS(XS_encrypt)
{
    INVOKE_FUNC(CMD_ENCRYPT)
}

XS(XS_decrypt)
{
    INVOKE_FUNC(CMD_DECRYPT)
}

extern "C"
XS(boot_xmldsig)
{
	dXSARGS;
	PERL_UNUSED_VAR(items);
	XS_VERSION_BOOTCHECK;

    if (!xml::init()) {
        croak("Error while XML init: %s\n", xml::getErrors().c_str());
    }
	newXS("xmldsig::sign", XS_sign, __FILE__);
	newXS("xmldsig::verify", XS_verify, __FILE__);
	newXS("xmldsig::encrypt", XS_encrypt, __FILE__);
	newXS("xmldsig::decrypt", XS_decrypt, __FILE__);

	XSRETURN_YES;
}

