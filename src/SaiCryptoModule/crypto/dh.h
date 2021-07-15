//
//  <dh.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef DH_H
#define DH_H

#include <encryptmethod.h>
#include <cryptopp/dh2.h>
#include <cryptopp/dh.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/misc.h>

class DH : public EncryptMethod
{
public:
    DH();
    Key *key;
    DH(Key *key);
    map<string, string> createKeys(map<string, string> params);
    map<string, string> makeSecretKey(map<string, string> params);
    map<string, string> exportKeys();
    map<string, string> importKeys(map<string, string> params);
};

#endif // DH_H
