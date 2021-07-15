//
//  <key.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef KEY_H
#define KEY_H

#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <QString>
#include <QSettings>
#include <QCoreApplication>
#include <QFile>
#include <QDir>
#include <QTextStream>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <encryptmethod.h>
#include <cryptlib.h>

using namespace std;

struct KeyPairHex {
  string publicKey;
  string privateKey;
};

class Key
{
    string id;
    string privateKey;
    string publicKey;
    string secretKey;
    string encryptMethodName;
    string curve;
public:
    Key();
    Key(string keyId);
    Key(const CryptoPP::PublicKey& key);
    void setKeyPair(KeyPairHex keyPair);
    void setEncryptionMethodName(string encryptMethodName);
    void setSecretKey(string secretKey);
    void SetCurve(string curve);
    string getEncryptionMethodName();
    string getKeyId();
    string getPublicKey();
    string getPrivateKey();
    string getSecretKey();
    string getCurve();
    void save();
    void load();
private slots:
    bool checkKeyExistence(string keyId);
};

#endif // KEY_H
