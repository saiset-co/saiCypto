//
//  <saicrypto.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "saicrypto.h"
#include <QDebug>
#include "queue.h"

EncryptMethod *encryptmethod;

SaiCrypto::SaiCrypto()
{
//    encryptmethod = new EncryptMethod();
}

QMap<QString, QString> SaiCrypto::createKeys(QMap<QString, QString> data)
{
    QMap<QString, QString> returnMap;
    map<string, string>returnedMap;

    bool error = false;

    QString method = data.value("method");
    QString keysize = data.value("keysize");
    QString curve = data.value("curve");

    map<string, string> params;

    try
    {
        if(method == "")
            throw NullSaiException("EMPTY_METHOD_VALUE");
        if(method != "ecdsa")
        {
            if(method == "dh" || method == "ecdh")
            {

            }
            else
            {
                if(keysize == "")
                    throw NullSaiException("EMPTY_KEYSIZE_VALUE");
                else
                    params.insert(pair<string, string>("keysize", keysize.toStdString()));
            }
        }
        else
        {
            if(curve == "" && method == "ecdsa")
                throw NullSaiException("EMPTY_CURVE_VALUE");
            else
                params.insert(pair<string, string>("curve", curve.toStdString()));
        }
        if(method == "rsa")
        {
            if(keysize.toInt() < 2048)
                throw NullSaiException("KEYSIZE_TOO_SHORT_FOR_RSA");
            encryptmethod = new RSA();
        }
        else if (method == "dsa")
        {
            encryptmethod = new DSA();
        }
        else if (method == "ecdsa")
        {
            encryptmethod = new ECDSA();
        }
        else if(method == "dh")
        {
            encryptmethod = new DH();
        }
        else if(method == "ecdh")
        {
            encryptmethod = new ECDH();
        }
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");
        returnedMap = encryptmethod->createKeys(params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }
    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::signStringByIdOfKeys(QMap<QString, QString> data)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string>returnedMap;

    QString message = data.value("message");
    QString id = data.value("id");

    try
    {
        if(message == "")
            throw NullSaiException("EMPTY_MESSAGE_VALUE");
        if(id == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        Key *key = new Key(id.toStdString());
        if(key->getKeyId() == "")
            throw NullSaiException("KEY_NOT_FOUND");

        if(key->getEncryptionMethodName() == "rsa")
        {
            encryptmethod = new RSA(key);
        }
        else if(key->getEncryptionMethodName() == "dsa")
        {
            encryptmethod = new DSA(key);
        }
        else if(key->getEncryptionMethodName() == "ecdsa")
        {
            encryptmethod = new ECDSA(key);
        }
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");

        returnedMap = encryptmethod->signMessage(message.toStdString());
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::verifySignature(QMap<QString, QString> data)
{
    bool error = false;

    QString message = data.value("message");
    QString signature = data.value("signature");
    QString method = data.value("method");
    QString e = data.value("e");
    QString n = data.value("n");
    QString curve = data.value("curve");
    QString publickey = data.value("public");

    QMap<QString, QString> returnMap;
    map<string, string>returnedMap;
    map<string, string> params;

    try
    {
        if(message == "")
            throw NullSaiException("EMPTY_MESSAGE_VALUE");
        if(signature == "")
            throw  NullSaiException("EMPTY_SIGNATURE_VALUE");
        if(method == "")
            throw NullSaiException("EMPTY_ENCRYPTION_METHOD");
        else
        {
            if(method == "rsa")
            {
                if(e == "")
                    throw NullSaiException("EMPTY_PUBLIC_EXPONENT_VALUE");
                else
                    params.insert(pair<string, string>("e", e.toStdString()));
                if(n == "")
                    throw NullSaiException("EMPTY_MODULUS_VALUE");
                else
                    params.insert(pair<string, string>("n", n.toStdString()));
            }
            else if(method == "dsa")
            {
                if(publickey == "")
                    throw NullSaiException("EMPTY_PUBLIC_KEY_VALUE");
                else
                    params.insert(pair<string, string>("public", publickey.toStdString()));

            }
            else if(method == "ecdsa")
            {
                if(curve == "")
                    throw NullSaiException("EMPTY_CURVE_VALUE");
                else
                    params.insert(pair<string, string>("curve", curve.toStdString()));
                if(publickey == "")
                    throw NullSaiException("EMPTY_PUBLIC_KEY_VALUE");
                else
                    params.insert(pair<string, string>("public", publickey.toStdString()));
            }
        }

        if(method == "rsa") {
            encryptmethod = new RSA();
        }
        else if(method == "dsa") {
            encryptmethod = new DSA();
        }
        else if(method == "ecdsa") {
            encryptmethod = new ECDSA();
        }
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");

        returnedMap = encryptmethod->verifySignature(message.toStdString(), signature.toStdString(), params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }
    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::importKeys(QMap<QString, QString> data)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    QString curve = data.value("curve");
    QString privatekey = data.value("private");
    QString publickey = data.value("public");
    QString method = data.value("method");
    QString d = data.value("d");
    QString e = data.value("e");
    QString n = data.value("n");

    try
    {
        if(method == "")
            throw NullSaiException("EMPTY_ENCRYPTION_METHOD");
        else
        {
            if(method == "rsa")
            {
                if(e == "")
                    throw NullSaiException("EMPTY_PUBLIC_EXPONENT_VALUE");
                else
                    params.insert(pair<string, string>("e", e.toStdString()));
                if(d == "")
                    throw NullSaiException("EMPTY_PRIVATE_EXPONENT_VALUE");
                else
                    params.insert(pair<string, string>("d", d.toStdString()));
                if(n == "")
                    throw NullSaiException("EMPTY_MODULUS_VALUE");
                else
                    params.insert(pair<string, string>("n", n.toStdString()));
            }
            else if(method == "dsa")
            {
                if(publickey == "")
                    throw NullSaiException("EMPTY_PUBLIC_KEY_VALUE");
                else
                    params.insert(pair<string, string>("public", publickey.toStdString()));

                if(privatekey == "")
                    throw NullSaiException("EMPTY_PRIVATE_KEY_VALUE");
                else
                    params.insert(pair<string, string>("private", privatekey.toStdString()));
            }
            else if(method == "dh")
            {
                if(publickey == "")
                    throw NullSaiException("EMPTY_PUBLIC_KEY_VALUE");
                else
                    params.insert(pair<string, string>("public", publickey.toStdString()));

                if(privatekey == "")
                    throw NullSaiException("EMPTY_PRIVATE_KEY_VALUE");
                else
                    params.insert(pair<string, string>("private", privatekey.toStdString()));
            }
            else if(method == "ecdh")
            {
                if(publickey == "")
                    throw NullSaiException("EMPTY_PUBLIC_KEY_VALUE");
                else
                    params.insert(pair<string, string>("public", publickey.toStdString()));

                if(privatekey == "")
                    throw NullSaiException("EMPTY_PRIVATE_KEY_VALUE");
                else
                    params.insert(pair<string, string>("private", privatekey.toStdString()));
            }
            else if(method == "ecdsa")
            {
                if(curve == "")
                    throw NullSaiException("EMPTY_CURVE_VALUE");
                else
                    params.insert(pair<string, string>("curve", curve.toStdString()));

                if(publickey == "")
                    throw NullSaiException("EMPTY_PUBLIC_KEY_VALUE");
                else
                    params.insert(pair<string, string>("public", publickey.toStdString()));

                if(privatekey == "")
                    throw NullSaiException("EMPTY_PRIVATE_KEY_VALUE");
                else
                    params.insert(pair<string, string>("private", privatekey.toStdString()));
            }
        }

        if(method == "rsa") {
            encryptmethod = new RSA();
        }
        else if(method == "dsa") {
            encryptmethod = new DSA();
        }
        else if(method == "ecdsa") {
            encryptmethod = new ECDSA();
        }
        else if(method == "dh")
        {
            encryptmethod = new DH();
        }
        else if(method == "ecdh")
        {
            encryptmethod = new ECDH();
        }
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");

        returnedMap = encryptmethod->importKeys(params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }
    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }
    return returnMap;
}

QMap<QString, QString> SaiCrypto::exportKeys(QMap<QString, QString> data)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;

    QString id = data.value("id");

    try
    {
        if(id == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        Key *key = new Key(id.toStdString());
        if(key->getKeyId() == "")
            throw NullSaiException("KEY_NOT_FOUND");

        if(key->getEncryptionMethodName() == "rsa") {
            encryptmethod = new RSA(key);
        }
        else if(key->getEncryptionMethodName() == "dsa") {
            encryptmethod = new DSA(key);
        }
        else if(key->getEncryptionMethodName() == "ecdsa") {
            encryptmethod = new ECDSA(key);
        }
        else if(key->getEncryptionMethodName() == "dh")
        {
            encryptmethod = new DH(key);
        }
        else if(key->getEncryptionMethodName() == "ecdh")
        {
            encryptmethod = new ECDH(key);
        }
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");

        returnedMap = encryptmethod->exportKeys();
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception &e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }
    return returnMap;
}

QMap<QString, QString> SaiCrypto::makeSecretKey(QMap<QString, QString> data)
{
    bool error = false;

    QString id = data.value("id");
    QString publickey = data.value("public");
    DH *dh;
    ECDH *ecdh;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    try
    {
        if(publickey == "")
            throw NullSaiException("EMPTY_PUBLIC_KEY_VALUE");
        else
            params.insert(pair<string, string>("public", publickey.toStdString()));

        if(id == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        Key *key = new Key(id.toStdString());
        if(key->getKeyId() == "")
            throw NullSaiException("KEY_NOT_FOUND");

        if(key->getEncryptionMethodName() == "dh")
            dh = new DH(key);
        else if(key->getEncryptionMethodName() == "ecdh")
            ecdh = new ECDH(key);
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");

        if(key->getEncryptionMethodName() == "dh")
            returnedMap = dh->makeSecretKey(params);
        if(key->getEncryptionMethodName() == "ecdh")
            returnedMap = ecdh->makeSecretKey(params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }
    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::encrypt(QMap<QString, QString> args)
{
    bool error = false;

    QString data = args.value("data");
    QString id = args.value("id");

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    try
    {
        if(data == "")
            throw NullSaiException("EMPTY_DATA_VALUE");

        if(id == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        Key *key = new Key(id.toStdString());
        if(key->getKeyId() == "")
            throw NullSaiException("KEY_NOT_FOUND");
        else
            params.insert(pair<string, string>("secret_id", id.toStdString()));

        if(key->getEncryptionMethodName() == "dh")
            encryptmethod = new AES();
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");

        returnedMap = encryptmethod->encrypt(data.toStdString(), params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }
    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::decrypt(QMap<QString, QString> args)
{
    bool error = false;

    QString cipher = args.value("cipher");
    QString id = args.value("id");

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    try
    {
        if(id == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        Key *key = new Key(id.toStdString());
        if(key->getKeyId() == "")
            throw NullSaiException("KEY_NOT_FOUND");
        else
            params.insert(pair<string, string>("secret_id", id.toStdString()));

        if(key->getEncryptionMethodName() == "dh")
            encryptmethod = new AES();
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");

        returnedMap = encryptmethod->decrypt(cipher.toStdString(), params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }
    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::createBtcKeys(QMap<QString, QString> args)
{
    args.empty();
    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;

    ECDSA *ecdsa;

    bool error = false;

    try
    {
        ecdsa = new ECDSA();
        returnedMap = ecdsa->createBtcKeys();
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception &e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }
    return returnMap;
}

QMap<QString, QString> SaiCrypto::createBtcAddress(QMap<QString, QString> args)
{
    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    ECDSA *ecdsa;

    bool error = false;

    QString id = args.value("id");
    QString publickey = args.value("public");
    string wif = (args.value("wif") == "" || args.value("wif") == "true") ? "true" : "false";
    params.insert(pair<string, string>("wif", wif));
    string compressed = (args.value("compressed") == "" || args.value("compressed") == "true") ? "true" : "false";
    params.insert(pair<string, string>("compressed", compressed));

    try
    {
        if(id != "")
        {
            Key *key = new Key(id.toStdString());
            if(key->getKeyId() == "")
                throw NullSaiException("KEY_NOT_FOUND");
            else
                ecdsa = new ECDSA(key);
        }
        else if(publickey != "")
            params.insert(pair<string, string>("public", publickey.toStdString()));
        else if(id == "" && publickey == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        returnedMap = ecdsa->createBtcAddress(params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception &e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::exportBtcKeys(QMap<QString, QString> args)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    QString id = args.value("id");
    string wif = (args.value("wif") == "" || args.value("wif") == "false") ? "false" : "true";
    params.insert(pair<string, string>("wif", wif));
    string compressed = (args.value("compressed") == "" || args.value("compressed") == "true") ? "true" : "false";
    params.insert(pair<string, string>("compressed", compressed));


    try
    {
        if(id == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        Key *key = new Key(id.toStdString());
        if(key->getKeyId() == "")
            throw NullSaiException("KEY_NOT_FOUND");

        ECDSA *ecdsa = new ECDSA(key);

        returnedMap = ecdsa->exportBtcKeys(params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception &e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }
    return returnMap;
}

QMap<QString, QString> SaiCrypto::importBtcKeys(QMap<QString, QString> args)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    QString privatekey = args.value("private");
    QString publickey = args.value("public");
    ECDSA *ecdsa;
    try
    {
        params.insert(pair<string, string>("public", publickey.toStdString()));

        if(privatekey == "")
            throw NullSaiException("EMPTY_PRIVATE_KEY_VALUE");
        else
            params.insert(pair<string, string>("private", privatekey.toStdString()));

        ecdsa = new ECDSA();
        returnedMap = ecdsa->importBtcKeys(params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }
    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }
    return returnMap;
}

QMap<QString, QString> SaiCrypto::signDataByBtcKeys(QMap<QString, QString> args)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string>returnedMap;
    map<string, string> params;

    QString data = args.value("data");
    QString id = args.value("id");
    QString type = args.value("type"); //tx, string
    QString encoding = args.value("encoding"); //der, p1363

    ECDSA *ecdsa;
    try
    {
        if(data == "")
            throw NullSaiException("EMPTY_DATA_VALUE");

        if(type == "")
            type = "string";
        else if(type != "" && type != "tx" && type != "string")
            throw UndefinedSaiException("UNDEFINED_DATA_TYPE");
        params.insert(pair<string, string>("type", type.toStdString()));

        if(encoding == "")
            encoding = "der";
        else if(encoding != "" && encoding != "p1363" && encoding != "der")
            throw UndefinedSaiException("UNDEFINED_ENCODING");
        params.insert(pair<string, string>("encoding", encoding.toStdString()));

        if(id == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        Key *key = new Key(id.toStdString());
        if(key->getKeyId() == "")
            throw NullSaiException("KEY_NOT_FOUND");

        if(key->getEncryptionMethodName() == "ecdsa")
            ecdsa = new ECDSA(key);
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");

        returnedMap = ecdsa->signDataBtc(data.toStdString(), params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::verifySignatureBtc(QMap<QString, QString> args)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    QString data = args.value("data");
    QString type = args.value("type"); //tx, string
    QString encoding  = args.value("encoding");
    QString signature = args.value("signature");
    QString publickey = args.value("public");

    ECDSA *ecdsa;
    try
    {
        if(type == "")
            type = "string";
        else if(type != "" && type != "tx" && type != "string")
            throw UndefinedSaiException("UNDEFINED_DATA_TYPE");
        params.insert(pair<string, string>("type", type.toStdString()));

        if(encoding == "")
            encoding = "der";
        else if(encoding != "" && encoding != "p1363" && encoding != "der")
            throw UndefinedSaiException("UNDEFINED_ENCODING");
        params.insert(pair<string, string>("encoding", encoding.toStdString()));

        if(data == "")
            throw NullSaiException("EMPTY_DATA_VALUE");
        if(signature == "")
            throw NullSaiException("EMPTY_SIGNATURE_VALUE");

        if(publickey == "")
            throw NullSaiException("EMPTY_PUBLIC_KEY_VALUE");
        else
            params.insert(pair<string, string>("public", publickey.toStdString()));

        ecdsa = new ECDSA();
        returnedMap = ecdsa->verifySignatureBtc(data.toStdString(), signature.toStdString(), params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::createEthKeys(QMap<QString, QString> args)
{
    args.empty();
    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;

    ECDSA *ecdsa;

    bool error = false;

    try
    {
        ecdsa = new ECDSA();
        returnedMap = ecdsa->createEthKeys();
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception &e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }
    return returnMap;
}

QMap<QString, QString> SaiCrypto::createEthAddress(QMap<QString, QString> args)
{
    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;
    ECDSA *ecdsa;

    bool error = false;

    QString id = args.value("id");
    QString publickey = args.value("public");

    try
    {
        if(id != "")
        {
            Key *key = new Key(id.toStdString());
            if(key->getKeyId() == "")
                throw NullSaiException("KEY_NOT_FOUND");
            else
                ecdsa = new ECDSA(key);
        }
        else if(publickey != "")
            params.insert(pair<string, string>("public", publickey.toStdString()));
        else if(id == "" && publickey == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        returnedMap = ecdsa->createEthAddress(params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception &e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::exportEthKeys(QMap<QString, QString> args)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;

    QString id = args.value("id");

    try
    {
        if(id == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        Key *key = new Key(id.toStdString());
        if(key->getKeyId() == "")
            throw NullSaiException("KEY_NOT_FOUND");

        ECDSA *ecdsa = new ECDSA(key);

        returnedMap = ecdsa->exportEthKeys();
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception &e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }
    return returnMap;
}

QMap<QString, QString> SaiCrypto::signDataByEthKeys(QMap<QString, QString> args)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    QString data = args.value("data");
    QString id = args.value("id");
    QString type = args.value("type"); //tx, string

    ECDSA *ecdsa;
    try
    {
        if(data == "")
            throw NullSaiException("EMPTY_DATA_VALUE");

        if(type == "")
            type = "string";
        else if(type != "" && type != "tx" && type != "string")
            throw UndefinedSaiException("UNDEFINED_DATA_TYPE");
        params.insert(pair<string, string>("type", type.toStdString()));

        if(id == "")
            throw NullSaiException("EMPTY_KEY_ID_VALUE");

        Key *key = new Key(id.toStdString());
        if(key->getKeyId() == "")
            throw NullSaiException("KEY_NOT_FOUND");

        if(key->getEncryptionMethodName() == "ecdsa")
            ecdsa = new ECDSA(key);
        else
            throw UndefinedSaiException("UNDEFINED_ENCRYPTION_METHOD");

        returnedMap = ecdsa->signDataEth(data.toStdString(), params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::verifySignatureEth(QMap<QString, QString> args)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    QString data = args.value("data");
    QString type = args.value("type"); //tx, string
    QString signature = args.value("signature");
    QString publickey = args.value("public");

    ECDSA *ecdsa;
    try
    {
        if(type == "")
            type = "string";
        else if(type != "" && type != "tx" && type != "string")
            throw UndefinedSaiException("UNDEFINED_DATA_TYPE");
        params.insert(pair<string, string>("type", type.toStdString()));

        if(data == "")
            throw NullSaiException("EMPTY_DATA_VALUE");
        if(signature == "")
            throw NullSaiException("EMPTY_SIGNATURE_VALUE");
        if(publickey == "")
            throw NullSaiException("EMPTY_PUBLIC_KEY_VALUE");
        else
            params.insert(pair<string, string>("public", publickey.toStdString()));
        ecdsa = new ECDSA();
        returnedMap = ecdsa->verifySignatureEth(data.toStdString(), signature.toStdString(), params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }

    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }

    return returnMap;
}

QMap<QString, QString> SaiCrypto::importEthKeys(QMap<QString, QString> args)
{
    bool error = false;

    QMap<QString, QString> returnMap;
    map<string, string> returnedMap;
    map<string, string> params;

    QString privatekey = args.value("private");
    QString publickey = args.value("public");

    ECDSA *ecdsa;
    try
    {
        params.insert(pair<string, string>("public", publickey.toStdString()));

        if(privatekey == "")
            throw NullSaiException("EMPTY_PRIVATE_KEY_VALUE");
        else
            params.insert(pair<string, string>("private", privatekey.toStdString()));

        ecdsa = new ECDSA();
        returnedMap = ecdsa->importEthKeys(params);
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }
    if(!error)
    {
        for (map<string, string>::iterator it=returnedMap.begin(); it!=returnedMap.end(); ++it)
        {
            returnMap.insert(QString::fromStdString(it->first), QString::fromStdString(it->second));
        }
    }
    return returnMap;
}

QMap<QString, QString> SaiCrypto::hash(QMap<QString, QString> args)
{
    bool error = false;

    QMap<QString, QString> returnMap;

    QString method = args.value("method");
    QString data = args.value("data");


    try
    {
        if(data == "")
            throw NullSaiException("EMPTY_DATA_VALUE");

        if(method == "sha256")
        {
            returnMap.insert("hash", QString::fromStdString(Hasher::sha256(data.toStdString())));
        }
        else if(method == "ripemd160")
        {
            returnMap.insert("hash", QString::fromStdString(Hasher::ripemd160(data.toStdString())));
        }
        else if(method == "keccak256")
        {
            returnMap.insert("hash", QString::fromStdString(Hasher::keccak256(data.toStdString())));
        }
        else
            throw UndefinedSaiException("UNDEFINED_HASH_METHOD");
    }
    catch (NullSaiException ex)
    {
        error = true;
        returnMap.insert("error", ex.whatQ());
    }
    catch (exception& e)
    {
        error = true;
        returnMap.insert("error", QString::fromStdString(e.what()));
    }
    return returnMap;
}
