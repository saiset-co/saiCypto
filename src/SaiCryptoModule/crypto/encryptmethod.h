//
//  <encryptmethod.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef ENCRYPTMETHOD_H
#define ENCRYPTMETHOD_H

#include <stdio.h>
#include <iostream>
#include <strstream>

#include <QString>

#include "key.h"
#include "crypto/converter.h"
#include "crypto/hasher.h"
#include "crypto/encoder.h"

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptlib.h>
#include <cryptopp/keccak.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/misc.h>
#include <ripemd.h>
#include <osrng.h>
#include <pssr.h>
#include <whrlpool.h>

#include <exceptions/undefinedsaiexception.h>

using namespace std;

class EncryptMethod
{
public:
    string ENCRYPTMETHOD_NAME;
    EncryptMethod();
    virtual map<string, string> createKeys(map<string, string> params);
    virtual map<string, string> signMessage(string message);
    virtual map<string, string> verifySignature(string message, string signature, map<string, string> params);
    virtual map<string, string> makeSecretKey(map<string, string> params);
    virtual map<string, string> exportKeys();
    virtual map<string, string> importKeys(map<string, string> params);
    virtual map<string, string> encrypt(string message, map<string, string> params);
    virtual map<string, string> decrypt(string cipher, map<string, string> params);
};

#endif
