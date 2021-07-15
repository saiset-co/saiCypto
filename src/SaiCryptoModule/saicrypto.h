//
//  <saicrypto.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include <iostream>
#include <stdio.h>

#include <QObject>
#include <QMap>
#include <QString>

#include <crypto/key.h>
#include <crypto/encryptmethod.h>
#include <crypto/rsa.h>
#include <crypto/ecdh.h>
#include <crypto/dsa.h>
#include <crypto/ecdsa.h>
#include <crypto/dh.h>
#include <crypto/aes.h>

#include <exceptions/undefinedsaiexception.h>
#include <exceptions/nullsaiexception.h>

class SaiCrypto : public QObject
{
    Q_OBJECT
public:
    SaiCrypto();
    EncryptMethod *encryptmethod;
    QMap<QString, QString> createKeys(QMap<QString, QString> data);
    QMap<QString, QString> signStringByIdOfKeys(QMap<QString, QString> data);
    QMap<QString, QString> verifySignature(QMap<QString, QString> data);
    QMap<QString, QString> importKeys(QMap<QString, QString> data);
    QMap<QString, QString> exportKeys(QMap<QString, QString> data);
    QMap<QString, QString> makeSecretKey(QMap<QString, QString> data);
    QMap<QString, QString> encrypt(QMap<QString, QString> args);
    QMap<QString, QString> decrypt(QMap<QString, QString> args);

    QMap<QString, QString> createBtcKeys(QMap<QString, QString> args);
    QMap<QString, QString> createBtcAddress(QMap<QString, QString> args);
    QMap<QString, QString> signDataByBtcKeys(QMap<QString, QString> args);
    QMap<QString, QString> verifySignatureBtc(QMap<QString, QString> args);
    QMap<QString, QString> exportBtcKeys(QMap<QString, QString> args);
    QMap<QString, QString> importBtcKeys(QMap<QString, QString> args);

    QMap<QString, QString> createEthKeys(QMap<QString, QString> args);
    QMap<QString, QString> createEthAddress(QMap<QString, QString> args);
    QMap<QString, QString> signDataByEthKeys(QMap<QString, QString> args);
    QMap<QString, QString> verifySignatureEth(QMap<QString, QString> args);
    QMap<QString, QString> exportEthKeys(QMap<QString, QString> args);
    QMap<QString, QString> importEthKeys(QMap<QString, QString> args);

    QMap<QString, QString> hash(QMap<QString, QString> args);

private slots:

};
