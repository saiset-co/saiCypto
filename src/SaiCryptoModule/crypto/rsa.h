//
//  <rsa.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef RSA_H
#define RSA_H

#include "encryptmethod.h"
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/queue.h>

class RSA : public EncryptMethod
{
public:
    RSA();
    RSA(Key *key);
    Key* key;
    map<string, string> createKeys(map<string, string> params);
    map<string, string> signMessage(string message);
    map<string, string> verifySignature(string message, string signature, map<string, string> params);
    map<string, string> exportKeys();
    map<string, string> importKeys(map<string, string> params);
};

#endif
