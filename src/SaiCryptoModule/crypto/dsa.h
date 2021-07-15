//
//  <dsa.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef DSA_H
#define DSA_H

#include "encryptmethod.h"
#include <cryptopp/dsa.h>
#include <cryptopp/gfpcrypt.h>
#include <cryptopp/pubkey.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modarith.h>
#include <cryptopp/integer.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/misc.h>
#include <cryptopp/algparam.h>

class DSA : public EncryptMethod
{

public:
    DSA();
    DSA(Key *key);
    Key* key;
    map<string, string> createKeys(map<string, string> params);
    map<string, string> signMessage(string message);
    map<string, string> verifySignature(string message, string signature, map<string, string> params);
    map<string, string> exportKeys();
    map<string, string> importKeys(map<string, string> params);
};

#endif
