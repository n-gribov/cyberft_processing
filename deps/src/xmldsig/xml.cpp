/*
    Signing and verifying XML Signature using xmlsec library
*/

#include <libxml/parser.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemastypes.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <xmlsec/xmlenc.h>

#include <vector>
#include <sstream>
#include <iostream>
#include <strings.h>
#include <syslog.h>
#include "xml.h"

// максимальное количество сертификатов/ключей, которыми можно
// одновременно зашифровать сессионный ключ при шифровании XML
#define MAX_KEY_NUM 16

string toHex(const string &s)
{
    static char digits[] = "0123456789ABCDEF";
    string result;

    for (uint i=0; i<s.size(); i++) {
        unsigned char c = s[i];
        result.push_back(digits[c>>4]);
        result.push_back(digits[c & 0x0F]);
    }
    return result;
} 

namespace xml {
    string xmlErrors;

    const xmlChar* ids[2]=
    {
        (xmlChar*) "Id",
        NULL
    };

    void errorFunc(void *ctx, const char* msg,...)
    {
#ifdef DEBUG
        va_list ap;
        va_start(ap, msg);
        vfprintf(ctx ? (FILE *) ctx : stderr, msg, ap);
        va_end(ap);
#else
        va_list ap;
        char *buf = NULL;
        int size = 0;

        // find out required buffer size
        va_start(ap, msg);
        size = vsnprintf(buf, size, msg, ap);
        va_end(ap);

        if (size <= 0) {
            xmlErrors.append("Error in format string. ");
            return;
        }
        if ((buf = (char *) malloc(size+1)) == NULL)
            return;

        va_start(ap, msg);
        size = vsnprintf(buf, size+1, msg, ap);
        va_end(ap);
        xmlErrors.append(buf, size);
        free(buf);
#endif
    }
}

bool xml::init()
{
    LIBXML_TEST_VERSION     // calls xmlInitParser() internally
    xmlGenericErrorFunc handler = (xmlGenericErrorFunc) errorFunc;
    initGenericErrorDefaultFunc(&handler);
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    xmlIndentTreeOutput = 1; 

    if (xmlSecInit() < 0) {
        errorFunc(stderr, "Error: xmlsec initialization failed.\n");
        return false;
    }

    if (xmlSecCheckVersion() != 1) {
        errorFunc(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        return false;
    }    

#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if (xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
        errorFunc(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                "that you have it installed and check shared libraries path\n"
                "(LD_LIBRARY_PATH) envornment variable.\n");
        return false;
    }
#endif

    if (xmlSecCryptoAppInit(NULL) < 0) {
        errorFunc(stderr, "Error: crypto initialization failed.\n");
        return false;
    }

    if(xmlSecCryptoInit() < 0) {
        errorFunc(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return false;
    }

    return true;
}

void xml::done()
{
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();

    xmlCleanupParser();
    xmlMemoryDump();
}

int registerNS(xmlXPathContextPtr context, map<string, string> &xmlns)
{
    int result = 0;

    for (map<string, string>::const_iterator it = xmlns.begin(); it != xmlns.end(); ++it) {
        if (xmlXPathRegisterNs(context, (const xmlChar*) it->first.c_str(), (const xmlChar*) it->second.c_str())) {
            xml::errorFunc(NULL, "can't register namespace '%s' ", it->first.c_str());
            result = -1;
        }
    }
    return result;
}


static xmlXPathObjectPtr getXPathNodes(xmlDocPtr doc, xmlChar *xpath, map<string, string> &xmlns, bool checkSingle = false)
{
    xmlXPathContextPtr context = NULL;
    xmlXPathObjectPtr result = NULL;

    context = xmlXPathNewContext(doc);
    if (context == NULL) {
        xml::errorFunc(NULL, "Error in xmlXPathNewContext. ");
        goto err;
    }
    if (registerNS(context, xmlns))
        goto err;
    result = xmlXPathEvalExpression(xpath, context);
    if (result == NULL) {
        xml::errorFunc(NULL, "Error in xmlXPathEvalExpression. ");
        goto err;
    }
    if (xmlXPathNodeSetIsEmpty(result->nodesetval)){
        xml::errorFunc(NULL, "XPath returned empty result. ");
        goto err;
    }
    if (checkSingle && result->nodesetval->nodeNr > 1) {
        xml::errorFunc(NULL, "More than one node selected. ");
        goto err;
    }

    if (context)
        xmlXPathFreeContext(context);
    return result;

err:
    if (context)
        xmlXPathFreeContext(context);
    if (result)
        xmlXPathFreeObject(result);
    return NULL;
}

static xmlXPathObjectPtr getSingleXPathNode(xmlDocPtr doc, xmlChar *xpath, std::map<std::string, std::string> &xmlns)
{
    return getXPathNodes(doc, xpath, xmlns, true);
}

bool xml::verify(const string &msg, const string &xsd_filename, const string &cert, const string &sigpath, map<string, string> &xmlns)
{
    bool result = false;
    string SD, AP, OP;
    vector<string> path;
    xmlDocPtr doc = NULL;
    xmlXPathObjectPtr object = NULL;
    xmlSecKeysMngrPtr xmlSecKeyMngr = NULL;
    xmlSecKeyPtr pkey = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;

    // load document
    doc = xmlReadMemory(msg.c_str(), msg.size(), NULL, NULL, 0);
    if (!doc) {
        errorFunc(stderr, "Could not parse input message. ");
        goto err;
    } 
    xmlSecAddIDs(doc, xmlDocGetRootElement(doc), ids);

    if (!xsd_filename.empty()) {
        // load xml schema
        // to load additional files from memory we should use xmlRegisterInputCallbacks()
        xmlSchemaParserCtxtPtr ctxtParser = xmlSchemaNewParserCtxt(xsd_filename.c_str());
        xmlSchemaSetParserErrors(ctxtParser, (xmlSchemaValidityErrorFunc) errorFunc, (xmlSchemaValidityWarningFunc) errorFunc, NULL);
        xmlSchemaPtr schema = xmlSchemaParse(ctxtParser);
        xmlSchemaFreeParserCtxt(ctxtParser);

        // validate document against schema
        xmlSchemaValidCtxtPtr ctxt = xmlSchemaNewValidCtxt(schema);
        xmlSchemaSetValidErrors(ctxt, (xmlSchemaValidityErrorFunc) errorFunc, (xmlSchemaValidityWarningFunc) errorFunc, NULL);
        int ret = xmlSchemaValidateDoc(ctxt, doc);
        xmlSchemaFreeValidCtxt(ctxt);
        xmlSchemaFree(schema);
        if (ret != 0) {
            errorFunc(NULL, "error validating schema. ");
            goto err;
        }
    }

    // find signature node
    object = getSingleXPathNode(doc, (xmlChar *) sigpath.c_str(), xmlns);
    if (!object) {
        errorFunc(NULL, "Error: failed to find signature tag. ");
        goto err;
    }

    // create keys manager
    xmlSecKeyMngr = xmlSecKeysMngrCreate();
    if (!xmlSecKeyMngr) {
        errorFunc(stderr, "Error: failed to create keys manager. ");
        goto err;
    }
    if (xmlSecCryptoAppDefaultKeysMngrInit(xmlSecKeyMngr) < 0) {
        errorFunc(stderr, "Error: failed to initialize keys manager. ");
        goto err;
    }

    // load trusted x509 certificate
    pkey = xmlSecCryptoAppKeyLoadMemory((xmlChar *) cert.c_str(), cert.size(), xmlSecKeyDataFormatCertPem, NULL, NULL, NULL);
    if (!pkey) {
        errorFunc(stderr, "Error: can not load certificate. ");
        goto err;
    }
    xmlSecCryptoAppDefaultKeysMngrAdoptKey(xmlSecKeyMngr, pkey);

    // verify signature
    dsigCtx = xmlSecDSigCtxCreate(xmlSecKeyMngr);
    if (!dsigCtx) {
        errorFunc(stderr, "Could not create dsigCtx. ");
        goto err;
    } 
    dsigCtx->flags |= XMLSEC_DSIG_FLAGS_IGNORE_MANIFESTS;
    if (xmlSecDSigCtxVerify(dsigCtx, object->nodesetval->nodeTab[0]) < 0) {
        errorFunc(stderr, "Error: signature verify. ");
        goto err;
    }

    if (dsigCtx->status != xmlSecDSigStatusSucceeded) {
        errorFunc(stderr, "Error: signature is INVALID. ");
        goto err;
    }

    result = true;

err:
    if (dsigCtx)
        xmlSecDSigCtxDestroy(dsigCtx);
    if (xmlSecKeyMngr)
        xmlSecKeysMngrDestroy(xmlSecKeyMngr);
    if (object)
        xmlXPathFreeObject(object);
    if (doc)
        xmlFreeDoc(doc);
    return result;
}

bool xml::sign(const string &in, string &out, const string &key, const string &cert, const string &pwd, const string &sigpath, map<string, string> &xmlns)
{
    bool result = false;
    xmlDocPtr doc = NULL;
    xmlXPathObjectPtr object = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    xmlChar *mem = NULL;
    int size = 0;

    // load document from memory
    doc = xmlReadMemory(in.c_str(), in.size(), NULL, NULL, 0);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        errorFunc(NULL, "Error: unable to parse file. ");
        goto done;      
    }
    xmlSecAddIDs(doc, xmlDocGetRootElement(doc), ids);

    // find signature node
    object = getSingleXPathNode(doc, (xmlChar *) sigpath.c_str(), xmlns);
    if (!object) {
        errorFunc(NULL, "Error: failed to find signature tag. ");
        goto done;
    }

    // create signature context
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if (!dsigCtx) {
        errorFunc(stderr, "Could not create dsigCtx. ");
        goto done;
    } 
    dsigCtx->flags |= XMLSEC_DSIG_FLAGS_IGNORE_MANIFESTS;
    if (!dsigCtx) {
        errorFunc(NULL,"Error: failed to create signature context. ");
        goto done;
    }
    dsigCtx->flags |= XMLSEC_DSIG_FLAGS_STORE_SIGNATURE | XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES | XMLSEC_DSIG_FLAGS_STORE_MANIFEST_REFERENCES;

    // load private key
    dsigCtx->signKey = xmlSecCryptoAppKeyLoad(key.c_str(), xmlSecKeyDataFormatPem, pwd.c_str(), NULL, NULL);
    if (!dsigCtx->signKey) {
        errorFunc(NULL,"Error: failed to load private pem key from \"%s\". ", key.c_str());
        goto done;
    }

    // load certificate and add to the key
    if (xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, cert.c_str(), xmlSecKeyDataFormatPem) < 0) {
        errorFunc(NULL,"Error: failed to load pem certificate \"%s\". ", cert.c_str());
        goto done;
    }

    // sign the template
    if (xmlSecDSigCtxSign(dsigCtx, object->nodesetval->nodeTab[0]) < 0) {
        errorFunc(NULL,"Error: signature failed. ");
        goto done;
    }

    xmlDocDumpFormatMemory(doc, &mem, &size, 0);
    if (size > 0) {
        result = true;
        out.assign((const char *) mem, size);
    }
    xmlFree(mem);

done:
    if (dsigCtx)
        xmlSecDSigCtxDestroy(dsigCtx);
    if (object)
        xmlXPathFreeObject(object);
    if (doc)
        xmlFreeDoc(doc); 
    return result;
}

// поддерживаемые шифры
static xmlSecTransformId getCipher(const string &s, xmlSecKeyDataId &dataId, xmlSecSize &sizeBits)
{
    if (s == "tripledes-cbc") {
        dataId = xmlSecKeyDataDesId;
        sizeBits = 192;
        return xmlSecTransformDes3CbcId;
    } else if (s == "aes128-cbc") {
        dataId = xmlSecKeyDataAesId;
        sizeBits = 128;
        return xmlSecTransformAes128CbcId;
    } else if (s == "aes192-cbc") {
        dataId = xmlSecKeyDataAesId;
        sizeBits = 192;
        return xmlSecTransformAes192CbcId;
    } else if (s == "aes256-cbc") {
        dataId = xmlSecKeyDataAesId;
        sizeBits = 256;
        return xmlSecTransformAes256CbcId;
    } else {
        dataId = xmlSecKeyDataDesId;
        sizeBits = 0;
        return xmlSecTransformIdUnknown;
    }
}

static bool getCertInfo(const string &path, string &fingerprint, string &serial, string &errmsg)
{
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp) {
        errmsg = "Can't open file ";
        errmsg.append(path);
        return false;
    }
    X509 *x = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!x) {
        errmsg = "Can't read certificate. ";
        errmsg.append(ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x), NULL);
    if (!bn) {
        errmsg = "Can't get serial number. ";
        errmsg.append(ERR_error_string(ERR_get_error(), NULL));
        X509_free(x);
        return false;
    }
    char *ser = BN_bn2dec(bn);
    serial.assign(ser);
    OPENSSL_free(ser);
    BN_free(bn);

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned len = sizeof md;
    const EVP_MD *digest = EVP_sha1();

    if (!X509_digest(x, digest, md, &len)) {
        errmsg = "Can't calculate fingerprint. ";
        errmsg.append(ERR_error_string(ERR_get_error(), NULL));
        X509_free(x);
        return false;
    }
    fingerprint.assign((char *) md, len);
    fingerprint = toHex(fingerprint);

    X509_free(x);
    return true;
}

bool xml::encrypt(const string &msg, vector<string> &certs, const string &sigpath, map<string, string> &xmlns, const string &cipher, string &out)
{
    bool result = false;
    xmlDocPtr doc = NULL;
    xmlXPathObjectPtr object = NULL;
    xmlSecKeysMngrPtr xmlSecKeyMngr = NULL;
    xmlSecKeyPtr pkey = NULL;
    xmlNodePtr encDataNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlNodePtr encKeyNode = NULL;
    xmlNodePtr keyInfoNode2 = NULL;
    xmlNodePtr x509DataNode = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    xmlChar *mem = NULL;
    int size = 0;
    xmlSecKeyDataId dataId;
    xmlSecSize sizeBits;
    vector<string> certNames;

    // разобрать входной XML
    doc = xmlReadMemory(msg.c_str(), msg.size(), NULL, NULL, 0);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        errorFunc(NULL, "Error: unable to parse file. ");
        goto done;      
    }

    // найти теги для шифрования с помощью XPath
    object = getXPathNodes(doc, BAD_CAST sigpath.c_str(), xmlns);
    if (!object) {
        errorFunc(NULL, "Error: failed to find tag for encryption. ");
        goto done;
    }

    // создать keys manager  по умолчанию для хранения сертификатов шифрования
    xmlSecKeyMngr = xmlSecKeysMngrCreate();
    if (!xmlSecKeyMngr) {
        errorFunc(stderr, "Error: failed to create keys manager. ");
        goto done;
    }
    if (xmlSecCryptoAppDefaultKeysMngrInit(xmlSecKeyMngr) < 0) {
        errorFunc(stderr, "Error: failed to initialize keys manager. ");
        goto done;
    }

    // прочитать все сертификаты и добавить их в manager с нужным именем
    size = certs.size();
    if (size > MAX_KEY_NUM) {
        errorFunc(NULL, "Error: too many certificates (>%i)", MAX_KEY_NUM);
        goto done;
    }
    for (int i = 0; i < size; i++) {
        string s = certs[i];
        if (!(pkey = xmlSecCryptoAppKeyLoad(s.c_str(), xmlSecKeyDataFormatCertPem, NULL, NULL, NULL))) {
            errorFunc(NULL, "Error: failed to load pem certificate \"%s\". ", s.c_str());
            goto done;
        }

        string fingerprint, serial, errmsg;
        if (!getCertInfo(s, fingerprint, serial, errmsg)) {
            errorFunc(NULL, "Error: getCertInfo \"%s\". ", errmsg.c_str());
            goto done;
        }
        certNames.push_back(fingerprint);

        if (xmlSecKeySetName(pkey, BAD_CAST fingerprint.c_str()) < 0) {
            errorFunc(NULL, "Error: failed to set key name for cert from \"%s\". ", s.c_str());
            goto done;
        }
        if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(xmlSecKeyMngr, pkey)) {
            errorFunc(NULL, "Error: failed to add key %s. ", s.c_str());
            goto done;
        }
        pkey = NULL; // добавленные ключи удалятся при уничтожении keys manager
    }

    // цикл по тегам, которые надо зашифровать
    for (int j=0; j < object->nodesetval->nodeNr; j++) {
        // создать программно шаблон шифрования с несколькими RSA ключами
        // которыми шифруется сессионный ключ
        encDataNode = xmlSecTmplEncDataCreate(doc, getCipher(cipher, dataId, sizeBits), NULL, xmlSecTypeEncElement, NULL, NULL); // or xmlSecTypeEncContent
        if (!encDataNode) {
            errorFunc(NULL, "Error: failed to create encryption template. ");
            goto done;
        }
        if (xmlSecTmplEncDataEnsureCipherValue(encDataNode) == NULL) {
            errorFunc(NULL, "Error: failed to add CipherValue node. ");
            goto done;
        }
        keyInfoNode = xmlSecTmplEncDataEnsureKeyInfo(encDataNode, NULL);
        if(keyInfoNode == NULL) {
            errorFunc(NULL, "Error: failed to add key info. ");
            goto done;
        }

        // цикл по переданным сертификатам различных клиентов
        for (int i = 0; i < size; i++) {
            encKeyNode = xmlSecTmplKeyInfoAddEncryptedKey(keyInfoNode, xmlSecTransformRsaPkcs1Id, NULL, NULL, NULL);
            if (encKeyNode == NULL) {
                errorFunc(NULL, "Error: failed to add key info. ");
                goto done;
            }
            if (xmlSecTmplEncDataEnsureCipherValue(encKeyNode) == NULL) {
                errorFunc(NULL, "Error: failed to add CipherValue node. ");
                goto done;
            }
            keyInfoNode2 = xmlSecTmplEncDataEnsureKeyInfo(encKeyNode, NULL);
            if(keyInfoNode2 == NULL) {
                errorFunc(NULL, "Error: failed to add key info. ");
                goto done;
            }
            if (xmlSecTmplKeyInfoAddKeyName(keyInfoNode2, BAD_CAST certNames[i].c_str()) == NULL) {
                errorFunc(NULL, "Error: failed to add key name. ");
                goto done;
            }
            if ((x509DataNode = xmlSecTmplKeyInfoAddX509Data(keyInfoNode2)) == NULL) {
                errorFunc(NULL, "Error: failed to add X509DATA. ");
                goto done;
            }
            if (xmlSecTmplX509DataAddIssuerSerial(x509DataNode) == NULL) {
                errorFunc(NULL, "Error: failed to add serial. ");
                goto done;
            }
            if (xmlSecTmplX509DataAddSubjectName(x509DataNode) == NULL) {
                errorFunc(NULL, "Error: failed to add subject name. ");
                goto done;
            }
        }

        encCtx = xmlSecEncCtxCreate(xmlSecKeyMngr);
        if (encCtx == NULL) {
            errorFunc(NULL, "Error: failed to create encryption context. ");
            goto done;
        }
        encCtx->encKey = xmlSecKeyGenerate(dataId, sizeBits, xmlSecKeyDataTypeSession);
        if (encCtx->encKey == NULL) {
            errorFunc(NULL, "Error: failed to generate session des key. ");
            goto done;
        }
        if (xmlSecEncCtxXmlEncrypt(encCtx, encDataNode, object->nodesetval->nodeTab[j]) < 0) {
            errorFunc(NULL, "Error: encryption failed. ");
            goto done;
        }
        xmlSecEncCtxDestroy(encCtx);
        encCtx = NULL;
        encDataNode = NULL; // удалится при удалении encCtx
    }

    xmlDocDumpFormatMemory(doc, &mem, &size, 0);
    if (size > 0) {
        result = true;
        out.assign((const char *) mem, size);
    }
    xmlFree(mem);

done:
    if (encCtx)
        xmlSecEncCtxDestroy(encCtx);
    if (encDataNode)
        xmlFreeNode(encDataNode);
    if (xmlSecKeyMngr)
        xmlSecKeysMngrDestroy(xmlSecKeyMngr);
    if (pkey)
        xmlSecKeyDestroy(pkey);
    if (object)
        xmlXPathFreeObject(object);
    if (doc)
        xmlFreeDoc(doc); 

    if (out.empty())
        out = getErrors();

    return result;
}

bool xml::decrypt(const string &in, const string &key, const string &pwd, const string &sigpath, map<string, string> &xmlns, string &out)
{
    bool result = false;
    xmlDocPtr doc = NULL;
    xmlSecKeyPtr pkey = NULL;
    xmlXPathObjectPtr object = NULL;
    xmlSecKeysMngrPtr xmlSecKeyMngr = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    xmlChar *mem = NULL;
    int size = 0;

    // разобрать входной XML
    doc = xmlReadMemory(in.c_str(), in.size(), NULL, NULL, 0);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        errorFunc(NULL, "Error: unable to parse file. ");
        goto done;      
    }

    // найти теги для расшифрования с помощью XPath
    object = getXPathNodes(doc, BAD_CAST sigpath.c_str(), xmlns);
    if (!object) {
        errorFunc(NULL, "Error: failed to find tag for encryption. ");
        goto done;
    }

    // создать keys manager  по умолчанию для хранения ключа расшифровки сессионного ключа
    xmlSecKeyMngr = xmlSecKeysMngrCreate();
    if (!xmlSecKeyMngr) {
        errorFunc(stderr, "Error: failed to create keys manager. ");
        goto done;
    }
    if (xmlSecCryptoAppDefaultKeysMngrInit(xmlSecKeyMngr) < 0) {
        errorFunc(stderr, "Error: failed to initialize keys manager. ");
        goto done;
    }

    pkey = xmlSecCryptoAppKeyLoad(key.c_str(), xmlSecKeyDataFormatPem, pwd.c_str(), NULL, NULL);
    if (!pkey) {
        errorFunc(NULL,"Error: failed to load private key \"%s\". ", key.c_str());
        goto done;
    }
    xmlSecCryptoAppDefaultKeysMngrAdoptKey(xmlSecKeyMngr, pkey);
    pkey = NULL;

    // цикл по тегам, которые надо расшифровать
    for (int i=0; i < object->nodesetval->nodeNr; i++) {
        encCtx = xmlSecEncCtxCreate(xmlSecKeyMngr);
        if (encCtx == NULL) {
            errorFunc(NULL, "Error: failed to create encryption context. ");
            goto done;
        } else {
            // иначе не будет искать дальше первого ключа
            encCtx->keyInfoReadCtx.maxEncryptedKeyLevel = MAX_KEY_NUM;
        }

        if ((xmlSecEncCtxDecrypt(encCtx, object->nodesetval->nodeTab[i]) < 0) || (encCtx->result == NULL)) {
            errorFunc(NULL, "Error: decryption failed. ");
            goto done;
        }
        xmlSecEncCtxDestroy(encCtx);
        encCtx = NULL;
    }

    xmlDocDumpFormatMemory(doc, &mem, &size, 0);
    if (size > 0) {
        result = true;
        out.assign((const char *) mem, size);
    }
    xmlFree(mem);

done:
    if (encCtx)
        xmlSecEncCtxDestroy(encCtx);
    if (xmlSecKeyMngr)
        xmlSecKeysMngrDestroy(xmlSecKeyMngr);
    if (pkey)
        xmlSecKeyDestroy(pkey);
    if (object)
        xmlXPathFreeObject(object);
    if (doc)
        xmlFreeDoc(doc); 

    if (out.empty())
        out = getErrors();
    return result;
}

string xml::getErrors()
{
    return xmlErrors;
}

void xml::clearErrors()
{
    xmlErrors.clear();
}

