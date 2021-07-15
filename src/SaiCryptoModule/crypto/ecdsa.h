//
//  <ecdsa.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef ECDSA_H
#define ECDSA_H

#include "encryptmethod.h"
#include <cryptopp/eccrypto.h>
#include "cryptopp/asn.h"
#include <cryptopp/dsa.h>
#include "cryptopp/oids.h"
#include <cryptopp/ecp.h>

class ECDSA : public EncryptMethod
{
public:
    ECDSA();
    ECDSA(Key *key);
    Key *key;
    map<string, string> createKeys(map<string, string> params);
    map<string, string> signMessage(string message);
    map<string, string> verifySignature(string message, string signature, map<string, string> params);
    map<string, string> exportKeys();
    map<string, string> importKeys(map<string, string> params);

    map<string, string> createBtcKeys();
    map<string, string> createBtcAddress(map<string, string> params);
    map<string, string> signDataBtc(string data, map<string, string> params);
    map<string, string> verifySignatureBtc(string data, string signature, map<string, string> params);
    map<string, string> exportBtcKeys(map<string, string> params);
    map<string, string> importBtcKeys(map<string, string> params);

    map<string, string> createEthKeys();
    map<string, string> createEthAddress(map<string, string> params);
    map<string, string> exportEthKeys();
    map<string, string> signDataEth(string data, map<string, string> params);
    map<string, string> verifySignatureEth(string data, string signature, map<string, string> params);
    map<string, string> importEthKeys(map<string, string> params);
};

#endif // ECDSA_H
