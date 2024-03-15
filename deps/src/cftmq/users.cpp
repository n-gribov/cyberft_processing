#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include "md5.h"
#include "sha256.h"
#include "users.h"

bool users::list::open(const std::string& source_path,const std::string& cache_path)
{
    db = new TreeDB;

    if (!db) {
        return false;
	}

    if (db->open(cache_path, TreeDB::OWRITER|TreeDB::OCREATE)) {
        location = source_path;
        cache_location = cache_path;
        FILE* fp = fopen(source_path.c_str(),"r");
        if(fp) {
            parse(fp);
            fclose(fp);
        }

        return true;
    }
    
    delete db;
    db = NULL;
        
    return false;
}

void users::list::close(void)
{
    if (db) {
        db->close();
        db = NULL;
        unlink(cache_location.c_str());
    }
}

bool users::list::parse(FILE* fp)
{
    char buf[BUFSIZ];

    while (fgets(buf, sizeof(buf), fp)) {
        char* p = strpbrk(buf,"#\r\n");
        if (p) {
            *p = 0;
		}
        if (!*buf) {
            continue;
		}

        p = strchr(buf, ':');
        if (p) {
            db->set(std::string(buf, p - buf), std::string(p + 1));
		}
    }

    return true;
}

bool users::list::get(const std::string& name, user& u)
{
    std::string value;

    if (!db || !db->get(name, &value)) {
        return false;
	}

	//syslog(LOG_INFO, "users::list::get value:%s", value.c_str());

    std::string::size_type n = value.find(':');
    if (n == std::string::npos) {
        return false;
	}

    std::string alg(value.substr(0,n));
    std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);
    if (alg == "md5") {
        u._alg = ALG_MD5;
	} else if (alg == "sha256") {
        u._alg = ALG_SHA256;
    } else {
        return false;
	}

    value.erase(0, n + 1);
    n = value.find(':');
    if (n == std::string::npos) {
        return false;
	}
    u._passcode = value.substr(0, n);

    value.erase(0, n+1);
    n = value.find(':');
    if (n == std::string::npos) {
        return false;
	}
    u._salt = value.substr(0, n);
    u._role = value.substr(n + 1);

    return true;
}

bool users::user::validate(const std::string& passcode)
{
    static const char t[] = "0123456789abcdef";
    int hash_len;   // in hex form
    unsigned char buf[BUFSIZ];

    if (_alg == ALG_MD5) {
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, (unsigned char*)passcode.c_str(), passcode.length());
        MD5_Update(&ctx, (unsigned char *)_salt.c_str(), _salt.length());
        MD5_Final(buf, &ctx);
        hash_len = 16 * 2;
    } else if (_alg == ALG_SHA256) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (unsigned char*)passcode.c_str(), passcode.length());
        sha256_update(&ctx, (unsigned char *)_salt.c_str(), _salt.length());
        sha256_final(&ctx, buf);
        hash_len = 32 * 2;
    } else {
        return false;
	}

    for (int i = 0, j = 0; i < hash_len; i += 2) {
        if (
			tolower(_passcode[i]) != t[(buf[j] >> 4) & 0x0f]
			|| tolower(_passcode[i + 1]) != t[buf[j] & 0x0f]
		) {
            return false;
		}
        j++;
    }

    return true;
}

