//
//  <key.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "key.h"
#include "cryptopp/osrng.h"

Key::Key()
{
    CryptoPP::SecByteBlock idByteBlock(10);
    CryptoPP::OS_GenerateRandomBlock(true, idByteBlock, idByteBlock.size());

    CryptoPP::HexEncoder hex(new CryptoPP::StringSink(this->id), false);
    hex.Put(idByteBlock, idByteBlock.size());
    hex.MessageEnd();
}

Key::Key(string keyId)
{
    QSettings settings(QCoreApplication::applicationDirPath() + "/config.ini", QSettings::IniFormat);
    string keypath = settings.value("keypath", "").toString().toStdString();

    if(keypath == "")
        keypath = QCoreApplication::applicationDirPath().toStdString() + "/keys";

    if(this->checkKeyExistence(keypath + "/" + keyId))
    {
        this->id = keyId;
        this->load();
    }
}

void Key::setKeyPair(KeyPairHex keyPair)
{
    this->privateKey = keyPair.privateKey;
    this->publicKey = keyPair.publicKey;
}

void Key::setEncryptionMethodName(string encryptMethodName)
{
    this->encryptMethodName = encryptMethodName;
}

void Key::setSecretKey(string secretKey)
{
    this->secretKey = secretKey;
}

void Key::SetCurve(string curve)
{
    this->curve = curve;
}

string Key::getEncryptionMethodName()
{
    return this->encryptMethodName;
}

string Key::getKeyId()
{
    return this->id;
}

string Key::getPrivateKey()
{
    return this->privateKey;
}

string Key::getPublicKey()
{
    return this->publicKey;
}

string Key::getSecretKey()
{
    return this->secretKey;
}

string Key::getCurve()
{
    return this->curve;
}

void Key::save()
{
    QSettings settings(QCoreApplication::applicationDirPath() + "/config.ini", QSettings::IniFormat);
    string keypath = settings.value("keypath", "").toString().toStdString();

    if(keypath == "")
    {
        keypath = QCoreApplication::applicationDirPath().toStdString() + "/keys";
        if(!QDir(QString::fromStdString(keypath)).exists())
        {
           QDir().mkdir(QString::fromStdString(keypath));
        }
    }

    if(!QDir(QString::fromStdString(keypath + "/" + this->id)).exists())
    {
       QDir().mkdir(QString::fromStdString(keypath + "/" + this->id));
    }

    QSettings key(QString::fromStdString(keypath + "/" + this->id + "/" + this->id + ".ini"), QSettings::IniFormat);
    key.setValue("private", QString::fromStdString(this->privateKey));
    key.setValue("public", QString::fromStdString(this->publicKey));
    key.setValue("secret", QString::fromStdString(this->secretKey));
    key.setValue("method", QString::fromStdString(this->encryptMethodName));
    key.setValue("curve", QString::fromStdString(this->curve));
}

void Key::load()
{
    QSettings settings(QCoreApplication::applicationDirPath() + "/config.ini", QSettings::IniFormat);
    string keypath = settings.value("keypath", "").toString().toStdString();

    if(keypath == "")
        keypath = QCoreApplication::applicationDirPath().toStdString() + "/keys";

    if(this->checkKeyExistence(keypath + "/" + this->getKeyId()))
    {
        QSettings key(QString::fromStdString(keypath + "/" + this->id + "/" + this->id + ".ini"), QSettings::IniFormat);
        this->privateKey = key.value("private", "").toString().toStdString();
        this->publicKey = key.value("public", "").toString().toStdString();
        this->secretKey = key.value("secret", "").toString().toStdString();
        this->encryptMethodName = key.value("method", "").toString().toStdString();
        this->curve = key.value("curve", "").toString().toStdString();
    }
}

bool Key::checkKeyExistence(string keyId)
{
    return QDir(QString::fromStdString(keyId)).exists();
}
