#ifndef ECDH_H
#define ECDH_H

#include <encryptmethod.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/misc.h>
#include <cryptopp/eccrypto.h>
#include "cryptopp/asn.h"
#include "cryptopp/oids.h"
#include <cryptopp/ecp.h>

class ECDH : public EncryptMethod
{
public:
    ECDH();    
    Key *key;
    ECDH(Key *key);
    map<string, string> createKeys(map<string, string> params);
    map<string, string> makeSecretKey(map<string, string> params);
    map<string, string> exportKeys();
    map<string, string> importKeys(map<string, string> params);
};

#endif // ECDH_H
