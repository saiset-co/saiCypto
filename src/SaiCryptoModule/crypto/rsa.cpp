//
//  <rsa.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "rsa.h"

RSA::RSA()
{
    this->key = new Key();
    this->ENCRYPTMETHOD_NAME = "rsa";
}

RSA::RSA(Key *key)
{
    this->key = key;
    this->ENCRYPTMETHOD_NAME = "rsa";
}

map<string, string> RSA::createKeys(map<string, string> params)
{
    string keysize = params.at("keysize");

    map<string, string>returnMap;

    KeyPairHex keyPair;
    CryptoPP::AutoSeededRandomPool rng;

    int modulusSize = 0;
    switch (stoi(keysize))
    {
        case 2048:
            modulusSize = 512;
            break;
        case 3072:
            modulusSize = 768;
            break;
//        case 4096:
//            modulusSize = 1024;
//            break;
        case 7680:
            modulusSize = 1920;
            break;
//        case 8192:
//            modulusSize = 2048;
//            break;
        case 15360:
            modulusSize = 3840;
            break;
        default:
            throw CryptoPP::InvalidArgument("RSA: not a valid key length");
    }

    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, stoi(keysize));

    CryptoPP::RSA::PublicKey publicKey(privateKey);

    publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
    privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    string publickey = Converter::integerToString(publicKey.GetModulus());
    if(static_cast<int>(publickey.length()) < modulusSize)
        publickey.insert(0, string(modulusSize - static_cast<int>(publickey.length()), '0'));

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("e", Converter::integerToString(publicKey.GetPublicExponent())));
    returnMap.insert(pair<string, string>("n", publickey));

    return returnMap;
}

map<string, string> RSA::signMessage(string message)
{
    map<string, string>returnMap;

    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

    CryptoPP::RSA::PublicKey publicKey;
    publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

    string signature;
    CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::Whirlpool>::Signer signer(privateKey);
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

    string modulus = Converter::integerToString(publicKey.GetModulus());
    int modulusSize = static_cast<int>(modulus.length());
    int signatureSize = 0;
    switch (modulusSize)
    {
        case 512:
            signatureSize = 512;
            break;
        case 768:
            signatureSize = 768;
            break;
        case 1920:
            signatureSize = 1920;
            break;
        case 3840:
            signatureSize = 3840;
            break;
        default:
            throw CryptoPP::InvalidArgument("RSA: Invalid public length");
    }

    if(static_cast<int>(signature.length()) < signatureSize)
        signature.insert(0, string(signatureSize - static_cast<int>(signature.length()), '0'));

    returnMap.insert(pair<string, string>("message", message));
    returnMap.insert(pair<string, string>("signature", signature));

    return returnMap;
}

map<string, string> RSA::verifySignature(string message, string signature, map<string, string> params)
{
    string n = params.at("n");
    string e = params.at("e");

    int modulusSize = static_cast<int>(n.length());
    int signatureSize = 0;
    switch (modulusSize)
    {
        case 512:
            signatureSize = 512;
            break;
        case 768:
            signatureSize = 768;
            break;
        case 1920:
            signatureSize = 1920;
            break;
        case 3840:
            signatureSize = 3840;
            break;
        default:
            throw CryptoPP::InvalidArgument("RSA: Invalid public length");
    }

    if(static_cast<int>(signature.length()) < signatureSize)
        throw CryptoPP::InvalidArgument("RSA: Invalid signature length");

    map<string, string> returnMap;

    CryptoPP::RSA::PublicKey publicKey;
    publicKey.Initialize(Converter::stringToInteger(n), Converter::stringToInteger(e));

    string decodedSignature;
    CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

    bool result = false;
    CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::Whirlpool>::Verifier verifier(publicKey);
    CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));


    returnMap.insert(pair<string, string>("valid", result ? "true" : "false"));

    return returnMap;
}

map<string, string> RSA::exportKeys()
{
    map<string, string>returnMap;

    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

    CryptoPP::RSA::PublicKey publicKey;
    publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());


    string publickey = Converter::integerToString(publicKey.GetModulus());
    string privatekey = Converter::integerToString(privateKey.GetPrivateExponent());
    int modulusSize = static_cast<int>(publickey.length());
    int privateSize = 0;

    switch (modulusSize)
    {
        case 512:
            privateSize = 512;
            break;
        case 768:
            privateSize = 768;
            break;
        case 1920:
            privateSize = 1920;
            break;
        case 3840:
            privateSize = 3840;
            break;
        default:
            if(modulusSize > 256 && modulusSize < 512)
            {
                modulusSize = 512;
                privateSize = 512;
            }
            else if(modulusSize > 512 && modulusSize < 768)
            {
                modulusSize = 768;
                privateSize = 768;
            }
            else if(modulusSize > 1900 && modulusSize < 1920)
            {
                modulusSize = 1920;
                privateSize = 1920;
            }
            else if(modulusSize > 3820 && modulusSize < 3840)
            {
                modulusSize = 3840;
                privateSize = 3840;
            }
            else
                throw CryptoPP::InvalidArgument("RSA: Invalid public length");
    }

    if(static_cast<int>(publickey.length()) < modulusSize)
        publickey.insert(0, string(modulusSize - static_cast<int>(publickey.length()), '0'));

    if(static_cast<int>(privatekey.length()) < privateSize)
        privatekey.insert(0, string(privateSize - static_cast<int>(privatekey.length()), '0'));

    returnMap.insert(pair<string, string>("d", privatekey));
    returnMap.insert(pair<string, string>("e", Converter::integerToString(publicKey.GetPublicExponent())));
    returnMap.insert(pair<string, string>("n", publickey));

    return returnMap;
}

map<string, string> RSA::importKeys(map<string, string> params)
{
    string n = params.at("n");
    string e = params.at("e");
    string d = params.at("d");

    int modulusSize = static_cast<int>(n.length());
    int privateSize = 0;

    switch (modulusSize)
    {
        case 512:
            privateSize = 512;
            break;
        case 768:
            privateSize = 768;
            break;
        case 1920:
            privateSize = 1920;
            break;
        case 3840:
            privateSize = 3840;
            break;
        default:
            throw CryptoPP::InvalidArgument("RSA: Invalid modulus length");
    }

    if(static_cast<int>(d.length()) != privateSize)
        throw CryptoPP::InvalidArgument("RSA: Invalid secret length");


    map<string, string> returnMap;

    KeyPairHex keyPair;

    CryptoPP::RSA::PublicKey publicKey;
    publicKey.Initialize(Converter::stringToInteger(n), Converter::stringToInteger(e));

    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.Initialize(Converter::stringToInteger(n), Converter::stringToInteger(e), Converter::stringToInteger(d));

    publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
    privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

    Key *key = new Key();
    key->setKeyPair(keyPair);
    key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    key->save();

    string publickey = Converter::integerToString(publicKey.GetModulus());

    if(static_cast<int>(publickey.length()) < modulusSize)
        publickey.insert(0, string(modulusSize - static_cast<int>(publickey.length()), '0'));

    returnMap.insert(pair<string, string>("id", key->getKeyId()));
    returnMap.insert(pair<string, string>("e", Converter::integerToString(publicKey.GetPublicExponent())));
    returnMap.insert(pair<string, string>("n", publickey));

    return returnMap;
}
