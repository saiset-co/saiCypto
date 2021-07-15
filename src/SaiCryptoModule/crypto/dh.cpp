//
//  <dh.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "dh.h"

DH::DH()
{
    this->key = new Key();
    this->ENCRYPTMETHOD_NAME = "dh";
}

DH::DH(Key *key)
{
    this->key = key;
    this->ENCRYPTMETHOD_NAME = "dh";
}

map<string, string> DH::createKeys(map<string, string> params)
{
    params.clear();
    map<string, string> returnMap;
    KeyPairHex keyPair;

    CryptoPP::Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
        "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
        "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
        "DF1FB2BC2E4A4371");

    CryptoPP::Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
        "855E6EEB22B3B2E5");

    CryptoPP::Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");

    CryptoPP::DH dh;
    CryptoPP::AutoSeededRandomPool rnd;

    string privatekey, publickey;
    CryptoPP::Integer privateKey, publicKey;

    dh.AccessGroupParameters().Initialize(p, q, g);

    if(!dh.GetGroupParameters().ValidateGroup(rnd, 3))
        throw runtime_error("Failed to validate prime and generator");

    CryptoPP::SecByteBlock priv(dh.PrivateKeyLength());
    CryptoPP::SecByteBlock pub(dh.PublicKeyLength());
    dh.GenerateKeyPair(rnd, priv, pub);

    privateKey.Decode(priv.BytePtr(), priv.SizeInBytes());
    publicKey.Decode(pub.BytePtr(), pub.SizeInBytes());

    privatekey = Converter::integerToString(privateKey);
    publickey = Converter::integerToString(publicKey);

    if(privatekey.length() < 40)
        privatekey.insert(0, string(40 - privatekey.length(), '0'));
    if(publickey.length() < 256)
        publickey.insert(0, string(256 - publickey.length(), '0'));
    keyPair.privateKey = privatekey;
    keyPair.publicKey = publickey;

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", publickey));

    return returnMap;
}

map<string, string> DH::makeSecretKey(map<string, string> params)
{
    map<string, string> returnMap;
    string publickey = params.at("public");
    string privatekey = this->key->getPrivateKey();

    CryptoPP::Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
        "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
        "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
        "DF1FB2BC2E4A4371");

    CryptoPP::Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
        "855E6EEB22B3B2E5");

    CryptoPP::Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");

    CryptoPP::DH dh;
    CryptoPP::AutoSeededRandomPool rnd;

    dh.AccessGroupParameters().Initialize(p, q, g);

    if(!dh.GetGroupParameters().ValidateGroup(rnd, 3))
        throw runtime_error("Failed to validate prime and generator");

    string privateKeyByte, publicKeyByte;

    CryptoPP::StringSource ss(privatekey, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(privateKeyByte)));
    const byte* privateKeyPtr = reinterpret_cast<const byte*>(privateKeyByte.data());
    CryptoPP::StringSource ss1(publickey, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(publicKeyByte)));
    const byte* publicKeyPtr = reinterpret_cast<const byte*>(publicKeyByte.data());

    CryptoPP::SecByteBlock privateKeyByteBlock(privateKeyPtr, 20);
    CryptoPP::SecByteBlock publicKeyByteBlock(publicKeyPtr, 128);
    CryptoPP::SecByteBlock secretKeyByteBlock(dh.AgreedValueLength());

    if(!dh.Agree(secretKeyByteBlock, privateKeyByteBlock, publicKeyByteBlock))
        throw runtime_error("Failed to reach shared secret");

    CryptoPP::Integer privateKey, publicKey, secretKey;

    privateKey.Decode(privateKeyByteBlock.BytePtr(), privateKeyByteBlock.SizeInBytes());
    publicKey.Decode(publicKeyByteBlock.BytePtr(), publicKeyByteBlock.SizeInBytes());
    secretKey.Decode(secretKeyByteBlock.BytePtr(), secretKeyByteBlock.SizeInBytes());

    Key *key = new Key();
    key->setEncryptionMethodName("dh");
    key->setSecretKey(Converter::integerToString(secretKey));
    key->save();

    returnMap.insert(pair<string, string>("secret_id", key->getKeyId()));

    return returnMap;
}

map<string, string> DH::exportKeys()
{
    map<string, string>returnMap;
    if(this->key->getSecretKey() == "")
    {
        string privatekey = this->key->getPrivateKey();
        string publickey = this->key->getPublicKey();

        if(privatekey.length() < 40)
            privatekey.insert(0, string(40 - privatekey.length(), '0'));
        if(publickey.length() < 256)
            publickey.insert(0, string(256 - publickey.length(), '0'));
        returnMap.insert(pair<string, string>("private", privatekey));
        returnMap.insert(pair<string, string>("public", publickey));
    }
    else
    {
        string secretkey = this->key->getSecretKey();
        if(secretkey.length() < 256)
            secretkey.insert(0, string(256 - secretkey.length(), '0'));
        returnMap.insert(pair<string, string>("secret", secretkey));
    }
    return returnMap;
}

map<string, string> DH::importKeys(map<string, string> params)
{
    string priv = params.at("private");
    string pub = params.at("public");

    map<string, string>returnMap;

    KeyPairHex keyPair;

    if(priv.length() < 40)
        throw CryptoPP::InvalidArgument("DH: not a valid private key length");
    if(pub.length() < 256)
        throw CryptoPP::InvalidArgument("Dh: not a valid public key length");
    keyPair.privateKey = priv;
    keyPair.publicKey = pub;

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", pub));
    return returnMap;
}
