#include "ecdh.h"

ECDH::ECDH()
{
    this->key = new Key();
    this->ENCRYPTMETHOD_NAME = "ecdh";
}

ECDH::ECDH(Key *key)
{
    this->key = key;
    this->ENCRYPTMETHOD_NAME = "ecdh";
}

map<string, string> ECDH::createKeys(map<string, string> params)
{
    params.clear();
    map<string, string> returnMap;
    KeyPairHex keyPair;

    CryptoPP::AutoSeededRandomPool rnd;

    CryptoPP::ECDH<CryptoPP::ECP>::Domain dh(CryptoPP::ASN1::secp256r1());

    string privatekey, publickey;
    CryptoPP::Integer privateKey, publicKey;

    CryptoPP::SecByteBlock priv(dh.PrivateKeyLength());
    CryptoPP::SecByteBlock pub(dh.PublicKeyLength());

    dh.GenerateKeyPair(rnd, priv, pub);

    privateKey.Decode(priv.BytePtr(), priv.SizeInBytes());
    publicKey.Decode(pub.BytePtr(), pub.SizeInBytes());

    privatekey = Converter::integerToString(privateKey);
    publickey = Converter::integerToString(publicKey);

//    if(privatekey.length() < 40)
//        privatekey.insert(0, string(40 - privatekey.length(), '0'));
//    if(publickey.length() < 256)
//        publickey.insert(0, string(256 - publickey.length(), '0'));
    keyPair.privateKey = privatekey;
    keyPair.publicKey = publickey;

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", publickey));

    return returnMap;
}

map<string, string> ECDH::makeSecretKey(map<string, string> params)
{
    map<string, string> returnMap;
    string publickey = params.at("public");
    string privatekey = this->key->getPrivateKey();

    CryptoPP::AutoSeededRandomPool rnd;

    CryptoPP::ECDH<CryptoPP::ECP>::Domain dh(CryptoPP::ASN1::secp256r1());

    string privateKeyByte, publicKeyByte;

    CryptoPP::StringSource ss(privatekey, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(privateKeyByte)));
    const byte* privateKeyPtr = reinterpret_cast<const byte*>(privateKeyByte.data());
    CryptoPP::StringSource ss1(publickey, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(publicKeyByte)));
    const byte* publicKeyPtr = reinterpret_cast<const byte*>(publicKeyByte.data());

    CryptoPP::SecByteBlock privateKeyByteBlock(privateKeyPtr, 64);
    CryptoPP::SecByteBlock publicKeyByteBlock(publicKeyPtr, 130);
    CryptoPP::SecByteBlock secretKeyByteBlock(dh.AgreedValueLength());

    if(!dh.Agree(secretKeyByteBlock, privateKeyByteBlock, publicKeyByteBlock))
        throw runtime_error("Failed to reach shared secret");

    CryptoPP::Integer privateKey, publicKey, secretKey;

    privateKey.Decode(privateKeyByteBlock.BytePtr(), privateKeyByteBlock.SizeInBytes());
    publicKey.Decode(publicKeyByteBlock.BytePtr(), publicKeyByteBlock.SizeInBytes());
    secretKey.Decode(secretKeyByteBlock.BytePtr(), secretKeyByteBlock.SizeInBytes());

    Key *key = new Key();
    key->setEncryptionMethodName("ecdh");
    key->setSecretKey(Converter::integerToString(secretKey));
    key->save();

    returnMap.insert(pair<string, string>("secret_id", key->getKeyId()));

    return returnMap;
}

map<string, string> ECDH::exportKeys()
{
    map<string, string>returnMap;
    if(this->key->getSecretKey() == "")
    {
        string privatekey = this->key->getPrivateKey();
        string publickey = this->key->getPublicKey();

//        if(privatekey.length() < 40)
//            privatekey.insert(0, string(40 - privatekey.length(), '0'));
//        if(publickey.length() < 256)
//            publickey.insert(0, string(256 - publickey.length(), '0'));
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

map<string, string> ECDH::importKeys(map<string, string> params)
{
    string priv = params.at("private");
    string pub = params.at("public");

    map<string, string>returnMap;

    KeyPairHex keyPair;

//    if(priv.length() < 40)
//        throw CryptoPP::InvalidArgument("DH: not a valid private key length");
//    if(pub.length() < 256)
//        throw CryptoPP::InvalidArgument("Dh: not a valid public key length");
    keyPair.privateKey = priv;
    keyPair.publicKey = pub;

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", pub));
    return returnMap;
}
