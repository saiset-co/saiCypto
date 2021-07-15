//
//  <ecdsa.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "ecdsa.h"

ECDSA::ECDSA()
{
    this->key = new Key();
    this->ENCRYPTMETHOD_NAME = "ecdsa";
}

ECDSA::ECDSA(Key *key)
{
    this->key = key;
    this->ENCRYPTMETHOD_NAME = "ecdsa";
}

map<string, string> ECDSA::createKeys(map<string, string> params)
{
    string curve = params.at("curve");

    map<string, string>returnMap;

    KeyPairHex keyPair;
    CryptoPP::AutoSeededRandomPool rng;

    string publickeyx, publickeyy;

    if(curve == "secp192k1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(rng, CryptoPP::ASN1::secp192k1());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 48)
            publickeyx.insert(0, string(48 - publickeyx.length(), '0'));
        if(publickeyy.length() < 48)
            publickeyy.insert(0, string(48 - publickeyy.length(), '0'));
    }
    else if(curve == "secp192r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(rng, CryptoPP::ASN1::secp192r1());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 48)
            publickeyx.insert(0, string(48 - publickeyx.length(), '0'));
        if(publickeyy.length() < 48)
            publickeyy.insert(0, string(48 - publickeyy.length(), '0'));
    }
    else if(curve == "secp224k1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(rng, CryptoPP::ASN1::secp224k1());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 56)
            publickeyx.insert(0, string(56 - publickeyx.length(), '0'));
        if(publickeyy.length() < 56)
            publickeyy.insert(0, string(56 - publickeyy.length(), '0'));
    }
    else if(curve == "secp224r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(rng, CryptoPP::ASN1::secp224r1());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 56)
            publickeyx.insert(0, string(56 - publickeyx.length(), '0'));
        if(publickeyy.length() < 56)
            publickeyy.insert(0, string(56 - publickeyy.length(), '0'));
    }
    else if(curve == "secp256k1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(rng, CryptoPP::ASN1::secp256k1());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 64)
            publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
        if(publickeyy.length() < 64)
            publickeyy.insert(0, string(64 - publickeyy.length(), '0'));
    }
    else if(curve == "secp256r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(rng, CryptoPP::ASN1::secp256r1());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 64)
            publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
        if(publickeyy.length() < 64)
            publickeyy.insert(0, string(64 - publickeyy.length(), '0'));
    }
    else if(curve == "secp384r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey privateKey;

        privateKey.Initialize(rng, CryptoPP::ASN1::secp384r1());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 96)
            publickeyx.insert(0, string(96 - publickeyx.length(), '0'));
        if(publickeyy.length() < 96)
            publickeyy.insert(0, string(96 - publickeyy.length(), '0'));
    }
    else if(curve == "secp521r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PrivateKey privateKey;

        privateKey.Initialize(rng, CryptoPP::ASN1::secp521r1());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 131)
            publickeyx.insert(0, string(131 - publickeyx.length(), '0'));
        if(publickeyy.length() < 131)
            publickeyy.insert(0, string(131 - publickeyy.length(), '0'));
    }
    else
        throw UndefinedSaiException("UNDEFINED_CURVE");

    this->key->setKeyPair(keyPair);
    this->key->SetCurve(curve);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", publickeyx + publickeyy));

    return returnMap;
}

map<string, string> ECDSA::signMessage(string message)
{
    map<string, string>returnMap;
    string signature;

    if(this->key->getCurve() == "secp192k1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(privateKey);
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

        if(signature.length() < 96)
            signature.insert(0, string(96 - signature.length(), '0'));
    }
    else if(this->key->getCurve() == "secp192r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(privateKey);
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

        if(signature.length() < 96)
            signature.insert(0, string(96 - signature.length(), '0'));
    }
    else if(this->key->getCurve() == "secp224k1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(privateKey);
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

        if(signature.length() < 112)
            signature.insert(0, string(112 - signature.length(), '0'));
    }
    else if(this->key->getCurve() == "secp224r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(privateKey);
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

        if(signature.length() < 112)
            signature.insert(0, string(112 - signature.length(), '0'));
    }
    else if(this->key->getCurve() == "secp256k1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(privateKey);
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

        if(signature.length() < 128)
            signature.insert(0, string(128 - signature.length(), '0'));
    }
    else if(this->key->getCurve() == "secp256r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(privateKey);
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

        if(signature.length() < 128)
            signature.insert(0, string(128 - signature.length(), '0'));
    }
    else if(this->key->getCurve() == "secp384r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA384>::Signer signer(privateKey);
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

        if(signature.length() < 192)
            signature.insert(0, string(192 - signature.length(), '0'));
    }
    else if(this->key->getCurve() == "secp521r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA512>::Signer signer(privateKey);
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

        if(signature.length() < 264)
            signature.insert(0, string(264 - signature.length(), '0'));
    }
    else
        throw UndefinedSaiException("UNDEFINED_CURVE");

    returnMap.insert(pair<string, string>("message", message));
    returnMap.insert(pair<string, string>("signature", signature));

    return returnMap;
}

map<string, string> ECDSA::verifySignature(string message, string signature, map<string, string> params)
{
    string curve = params.at("curve");
    string publickey = params.at("public");

    map<string, string>returnMap;

    string decodedSignature;

    bool result = false;

    if(curve == "secp192k1")
    {
        if(signature.length() < 96)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid signature length");

        if(publickey.length() < 96)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp192k1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(publicKey);
        CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    else if(curve == "secp192r1")
    {
        if(signature.length() < 96)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid signature length");

        if(publickey.length() < 96)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp192r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(publicKey);
        CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    else if(curve == "secp224k1")
    {
        if(signature.length() < 116)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid signature length");

        if(publickey.length() < 112)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp224k1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(publicKey);
        CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    else if(curve == "secp224r1")
    {
        if(signature.length() < 112)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid signature length");

        if(publickey.length() < 112)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp224r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(publicKey);
        CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    else if(curve == "secp256k1")
    {
        if(signature.length() < 128)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid signature length");

        if(publickey.length() < 128)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp256k1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(publicKey);
        CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    else if(curve == "secp256r1")
    {
        if(signature.length() < 128)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid signature length");

        if(publickey.length() < 128)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp256r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(publicKey);
        CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    else if(curve == "secp384r1")
    {
        if(signature.length() < 192)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid signature length");

        if(publickey.length() < 192)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp384r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA384>::Verifier verifier(publicKey);
        CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    else if(curve == "secp521r1")
    {
        if(signature.length() < 264)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid signature length");

        if(publickey.length() < 262)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp521r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

        CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA512>::Verifier verifier(publicKey);
        CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    else
        throw UndefinedSaiException("UNDEFINED_CURVE");

    returnMap.insert(pair<string, string>("valid", result ? "true" : "false"));

    return returnMap;
}

map<string, string> ECDSA::importKeys(map<string, string> params)
{
    string curve = params.at("curve");
    string privatekey = params.at("private");
    string publickey = params.at("public");

    map<string, string>returnMap;

    KeyPairHex keyPair;
    CryptoPP::AutoSeededRandomPool rng;

    string publickeyx, publickeyy;

    if(curve == "secp192k1")
    {
        if(publickey.length() < 96)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        if(privatekey.length() < 48)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid private length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp192k1()), Converter::stringToInteger(privatekey));

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp192k1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 48)
            publickeyx.insert(0, string(48 - publickeyx.length(), '0'));
        if(publickeyy.length() < 48)
            publickeyy.insert(0, string(48 - publickeyy.length(), '0'));
    }
    else if(curve == "secp192r1")
    {
        if(publickey.length() < 96)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        if(privatekey.length() < 48)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid private length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp192r1()), Converter::stringToInteger(privatekey));

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp192r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 48)
            publickeyx.insert(0, string(48 - publickeyx.length(), '0'));
        if(publickeyy.length() < 48)
            publickeyy.insert(0, string(48 - publickeyy.length(), '0'));
    }
    else if(curve == "secp224k1")
    {
        if(publickey.length() < 112)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        if(privatekey.length() < 56)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid private length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp224k1()), Converter::stringToInteger(privatekey));

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp224k1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 56)
            publickeyx.insert(0, string(56 - publickeyx.length(), '0'));
        if(publickeyy.length() < 56)
            publickeyy.insert(0, string(56 - publickeyy.length(), '0'));
    }
    else if(curve == "secp224r1")
    {
        if(publickey.length() < 112)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        if(privatekey.length() < 56)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid private length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp224r1()), Converter::stringToInteger(privatekey));

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp224r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 56)
            publickeyx.insert(0, string(56 - publickeyx.length(), '0'));
        if(publickeyy.length() < 56)
            publickeyy.insert(0, string(56 - publickeyy.length(), '0'));
    }
    else if(curve == "secp256k1")
    {
        if(publickey.length() < 128)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        if(privatekey.length() < 64)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid private length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp256k1()), Converter::stringToInteger(privatekey));

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp256k1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 64)
            publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
        if(publickeyy.length() < 64)
            publickeyy.insert(0, string(64 - publickeyy.length(), '0'));
    }
    else if(curve == "secp256r1")
    {
        if(publickey.length() < 128)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        if(privatekey.length() < 64)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid private length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;

        privateKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp256r1()), Converter::stringToInteger(privatekey));

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp256r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 64)
            publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
        if(publickeyy.length() < 64)
            publickeyy.insert(0, string(64 - publickeyy.length(), '0'));
    }
    else if(curve == "secp384r1")
    {
        if(publickey.length() < 192)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        if(privatekey.length() < 96)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid private length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey privateKey;

        privateKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp384r1()), Converter::stringToInteger(privatekey));

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp384r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 96)
            publickeyx.insert(0, string(96 - publickeyx.length(), '0'));
        if(publickeyy.length() < 96)
            publickeyy.insert(0, string(96 - publickeyy.length(), '0'));
    }
    else if(curve == "secp521r1")
    {
        if(publickey.length() < 262)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid public length");

        if(privatekey.length() < 131)
            throw CryptoPP::InvalidArgument("ECDSA: not a valid private length");

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PrivateKey privateKey;

        privateKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp521r1()), Converter::stringToInteger(privatekey));

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PublicKey publicKey;

        publicKey.Initialize(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp521r1()), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

        publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
        privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

        if(publickeyx.length() < 131)
            publickeyx.insert(0, string(131 - publickeyx.length(), '0'));
        if(publickeyy.length() < 131)
            publickeyy.insert(0, string(131 - publickeyy.length(), '0'));
    }
    else
        throw UndefinedSaiException("UNDEFINED_CURVE");

    Key *key = new Key();
    key->setKeyPair(keyPair);
    key->SetCurve(curve);
    key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    key->save();

    returnMap.insert(pair<string, string>("id", key->getKeyId()));
    returnMap.insert(pair<string, string>("public", publickeyx + publickeyy));

    return returnMap;
}

map<string, string> ECDSA::exportKeys()
{
    map<string, string> returnMap;
    string publickeyx, publickeyy, privatekey;

    if(this->key->getCurve() == "secp192k1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
        privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

        if(publickeyx.length() < 48)
            publickeyx.insert(0, string(48 - publickeyx.length(), '0'));
        if(publickeyy.length() < 48)
            publickeyy.insert(0, string(48 - publickeyy.length(), '0'));
        if(privatekey.length() < 48)
            privatekey.insert(0, string(48 - privatekey.length(), '0'));
    }
    else if(this->key->getCurve() == "secp192r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
        privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

        if(publickeyx.length() < 48)
            publickeyx.insert(0, string(48 - publickeyx.length(), '0'));
        if(publickeyy.length() < 48)
            publickeyy.insert(0, string(48 - publickeyy.length(), '0'));
        if(privatekey.length() < 48)
            privatekey.insert(0, string(48 - privatekey.length(), '0'));
    }
    else if(this->key->getCurve() == "secp224k1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
        privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

        if(publickeyx.length() < 56)
            publickeyx.insert(0, string(56 - publickeyx.length(), '0'));
        if(publickeyy.length() < 56)
            publickeyy.insert(0, string(56 - publickeyy.length(), '0'));
        if(privatekey.length() < 56)
            privatekey.insert(0, string(56 - privatekey.length(), '0'));
    }
    else if(this->key->getCurve() == "secp224r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
        privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

        if(publickeyx.length() < 56)
            publickeyx.insert(0, string(56 - publickeyx.length(), '0'));
        if(publickeyy.length() < 56)
            publickeyy.insert(0, string(56 - publickeyy.length(), '0'));
        if(privatekey.length() < 56)
            privatekey.insert(0, string(56 - privatekey.length(), '0'));
    }
    else if(this->key->getCurve() == "secp256k1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
        privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

        if(publickeyx.length() < 64)
            publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
        if(publickeyy.length() < 64)
            publickeyy.insert(0, string(64 - publickeyy.length(), '0'));
        if(privatekey.length() < 64)
            privatekey.insert(0, string(64 - privatekey.length(), '0'));
    }
    else if(this->key->getCurve() == "secp256r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
        privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

        if(publickeyx.length() < 64)
            publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
        if(publickeyy.length() < 64)
            publickeyy.insert(0, string(64 - publickeyy.length(), '0'));
        if(privatekey.length() < 64)
            privatekey.insert(0, string(64 - privatekey.length(), '0'));
    }
    else if(this->key->getCurve() == "secp384r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey publicKey;
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
        privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

        if(publickeyx.length() < 96)
            publickeyx.insert(0, string(96 - publickeyx.length(), '0'));
        if(publickeyy.length() < 96)
            publickeyy.insert(0, string(96 - publickeyy.length(), '0'));
        if(privatekey.length() < 96)
            privatekey.insert(0, string(96 - privatekey.length(), '0'));
    }
    else if(this->key->getCurve() == "secp521r1")
    {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey privateKey;
        privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey publicKey;
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

        publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
        publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
        privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

        if(publickeyx.length() < 131)
            publickeyx.insert(0, string(131 - publickeyx.length(), '0'));
        if(publickeyy.length() < 131)
            publickeyy.insert(0, string(131 - publickeyy.length(), '0'));
        if(privatekey.length() < 131)
            privatekey.insert(0, string(131 - privatekey.length(), '0'));
    }
    else
        throw UndefinedSaiException("UNDEFINED_CURVE");

    returnMap.insert(pair<string, string>("private", privatekey));
    returnMap.insert(pair<string, string>("public", publickeyx + publickeyy));
    returnMap.insert(pair<string, string>("curve", this->key->getCurve()));

    return returnMap;
}

map<string, string> ECDSA::createBtcKeys()
{
    map<string, string> returnMap;

    KeyPairHex keyPair;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

    CryptoPP::AutoSeededRandomPool rng;
    privateKey.Initialize(rng, CryptoPP::ASN1::secp256k1());
    privateKey.MakePublicKey(publicKey);

    publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
    privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    string publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
    string publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

    if(publickeyx.length() < 64)
        publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
    if(publickeyy.length() < 64)
        publickeyy.insert(0, string(64 - publickeyy.length(), '0'));

    string oddFlag;
    if(((CryptoPP::Integer)(publicKey.GetPublicElement().y)).IsOdd())
    {
        oddFlag = "03";
    }
    else
    {
        oddFlag = "02";
    }

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", publickeyx.insert(0, oddFlag)));

    return returnMap;
}

map<string, string> ECDSA::createBtcAddress(map<string, string> params)
{
    map<string, string> returnMap;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    string publickey;
    string wif = params.at("wif");
    string compressed = params.at("compressed");

    if (params.find("public") == params.end())
    {
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());
        if(compressed == "true")
        {
            string oddFlag;
            if(((CryptoPP::Integer)(publicKey.GetPublicElement().y)).IsOdd())
            {
                oddFlag = "03";
            }
            else
            {
                oddFlag = "02";
            }
            publickey = ((string)(Converter::integerToString(publicKey.GetPublicElement().x))).insert(0, oddFlag);
        }
        else
            publickey = ((string)(Converter::integerToString(publicKey.GetPublicElement().x) + Converter::integerToString(publicKey.GetPublicElement().y))).insert(0, "04");
    }
    else
    {
        publickey = params.at("public");
        if(publickey.length() != 66 && publickey.length() != 130)
            throw CryptoPP::InvalidArgument("BTC: not a valid btc public key length");
    }

    string sha256 = Hasher::sha256(publickey);
    string ripemd160 = Hasher::ripemd160(sha256);
    string extendedrip = ripemd160.insert(0, "6f");
    string firsthash = Hasher::sha256(extendedrip);
    string doublehash = Hasher::sha256(firsthash);
    string checksum = doublehash.substr(0, 8);
    string address = extendedrip.insert(extendedrip.size(), checksum);

    if(wif == "true")
    {
        address = Encoder::base58(address);
        address = address.substr(1);
    }

    returnMap.insert(pair<string, string>("address", address));
    return returnMap;
}

map<string, string> ECDSA::exportBtcKeys(map<string, string> params)
{
    map<string, string> returnMap;
    string wif = params.at("wif");
    string compressed = params.at("compressed");

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

    string publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
    string publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
    string oddFlag;
    if(((CryptoPP::Integer)(publicKey.GetPublicElement().y)).IsOdd())
    {
        oddFlag = "03";
    }
    else
    {
        oddFlag = "02";
    }
    string publickey;
    string privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

    if(privatekey.length() < 64)
        privatekey.insert(0, string(64 - privatekey.length(), '0'));
    if(publickeyx.length() < 64)
        publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
    if(publickeyy.length() < 64)
        publickeyy.insert(0, string(64 - publickeyy.length(), '0'));

    if(compressed == "false" && wif == "false")
    {
        publickey = (publickeyx + publickeyy).insert(0, "04");
    }
    else if(compressed == "true" && wif == "false")
    {
        publickey = publickeyx.insert(0, oddFlag);
    }
    else if(compressed == "true" && wif == "true")
    {
        privatekey = privatekey.insert(0, "ef");
        privatekey = privatekey.insert(privatekey.size(), "01");

        string firsthash = Hasher::sha256(privatekey);
        string doublehash = Hasher::sha256(firsthash);
        string checksum = doublehash.substr(0, 8);
        privatekey = privatekey.insert(privatekey.size(), checksum);

        privatekey = Encoder::base58(privatekey);
        privatekey = privatekey.substr(1);

        publickey = publickeyx.insert(0, oddFlag);
    }
    else
    {
        privatekey = privatekey.insert(0, "ef");

        string firsthash = Hasher::sha256(privatekey);
        string doublehash = Hasher::sha256(firsthash);
        string checksum = doublehash.substr(0, 8);
        privatekey = privatekey.insert(privatekey.size(), checksum);

        privatekey = Encoder::base58(privatekey);
        privatekey = privatekey.substr(1);

        publickey = (publickeyx + publickeyy).insert(0, "04");
    }

    returnMap.insert(pair<string, string>("private", privatekey));
    returnMap.insert(pair<string, string>("public", publickey));

    return returnMap;
}

map<string, string> ECDSA::importBtcKeys(map<string, string> params)
{
    map<string, string> returnMap;
    string privatekey = params.at("private");
    string publickey = params.at("public");

    CryptoPP::Integer privKey;

    switch (privatekey.length()) {
    case 64:
        privKey = Converter::stringToInteger(privatekey);
        break;
//    case 51:
//        wif, uncompressed;
//        break;
//    case 52:
//        wif, compressed;
//        break;
    default:
        throw CryptoPP::InvalidArgument("BTC: not a valid private length");
        break;
    }

    KeyPairHex keyPair;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

    privateKey.Initialize(CryptoPP::ASN1::secp256k1(), privKey);

    if(publickey != "")
    {
        publickey = publickey.substr(2);
        if(publickey.length() < 128)
            throw CryptoPP::InvalidArgument("BTC: not a valid public length");
        publicKey.Initialize(CryptoPP::ASN1::secp256k1(), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)),
                                                                             Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));
    }
    else
        privateKey.MakePublicKey(publicKey);

    publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
    privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    string publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
    string publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

    string oddFlag;
    if(((CryptoPP::Integer)(publicKey.GetPublicElement().y)).IsOdd())
    {
        oddFlag = "03";
    }
    else
    {
        oddFlag = "02";
    }

    if(publickeyx.length() < 64)
        publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
    if(publickeyy.length() < 64)
        publickeyy.insert(0, string(64 - publickeyy.length(), '0'));

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", publickeyx.insert(0, oddFlag)));

    return returnMap;
}

map<string, string> ECDSA::signDataBtc(string data, map<string, string> params)
{
    map<string, string>returnMap;
    string type = params.at("type");
    string encoding = params.at("encoding");

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

    string signature;
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(privateKey);
    CryptoPP::AutoSeededRandomPool rng;

    if(type == "string")
        CryptoPP::StringSource ss(data, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));
    else if(type == "tx")
    {
        CryptoPP::StringSource ss(data, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

        if(encoding == "der")
        {
            byte P1363Signature[signature.size() / 2];
            Converter::stringHexToByteArray2(P1363Signature, signature);

            byte DERSignature[72];
            CryptoPP::DSAConvertSignatureFormat(DERSignature, sizeof(DERSignature), CryptoPP::DSA_DER, P1363Signature, sizeof(P1363Signature), CryptoPP::DSA_P1363);

            signature = Converter::ByteArrayToHexString(DERSignature, sizeof(DERSignature));

            int sizeInHex = stoi(signature.substr(2, 2));

            int size = 0;

            switch (sizeInHex) {
            case 46:
                size = 0;
                break;
            case 45:
                size = 2;
                break;
            case 44:
                size = 4;
                break;
            default:
                break;
            }

            signature = signature.substr(0, signature.length() - size);
        }
    }

    returnMap.insert(pair<string, string>("data", data));
    returnMap.insert(pair<string, string>("signature", signature));

    return returnMap;
}

map<string, string> ECDSA::verifySignatureBtc(string data, string signature, map<string, string> params)
{
    map<string, string>returnMap;
    string publickey = params.at("public");
    string type = params.at("type");
    string encoding = params.at("encoding");

    if(signature.length() < 128)
        throw CryptoPP::InvalidArgument("BTC: not a valid btc signature length");
    if(publickey.length() < 128)
        throw CryptoPP::InvalidArgument("BTC: not a valid public length");

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

    /*switch (publickey.length()) {
    case 68:
        publicKey.AccessGroupParameters().SetPointCompression(true);
        publicKey.Load(CryptoPP::StringSource(publickey, true).Ref());
        break;
    case 132:
        publicKey.Load(CryptoPP::StringSource(publickey, true).Ref());
        break;
    default:
        throw CryptoPP::InvalidArgument("BTC: not a valid public length");
        break;
    }*/

    if(publickey.length() == 130)
        publickey = publickey.substr(2);

    publicKey.Initialize(CryptoPP::ASN1::secp256k1(), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

    bool result = false;
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(publicKey);
    if(type == "string")
    {
        string decodedSignature;
        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));
        CryptoPP::StringSource ss2(decodedSignature + data, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    else if(type == "tx")
    {
        if(encoding == "der")
        {
            byte DERSignature[signature.size() / 2];
            Converter::stringHexToByteArray2(DERSignature, signature);

            byte P1363Signature[64];
            CryptoPP::DSAConvertSignatureFormat(P1363Signature, sizeof(P1363Signature), CryptoPP::DSA_P1363, DERSignature, sizeof(DERSignature), CryptoPP::DSA_DER);

            signature = Converter::ByteArrayToHexString(P1363Signature, sizeof(P1363Signature));
        }
        string decodedSignature;
        CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));
        CryptoPP::StringSource ss2(decodedSignature + data, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }
    returnMap.insert(pair<string, string>("data", data));
    returnMap.insert(pair<string, string>("signature", signature));
    returnMap.insert(pair<string, string>("valid", result ? "true" : "false"));

    return returnMap;
}

map<string, string> ECDSA::createEthKeys()
{
    map<string, string> returnMap;

    KeyPairHex keyPair;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

    CryptoPP::AutoSeededRandomPool rng;
    privateKey.Initialize(rng, CryptoPP::ASN1::secp256k1());
    privateKey.MakePublicKey(publicKey);

    publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
    privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

    string publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
    string publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

    if(publickeyx.length() < 64)
        publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
    if(publickeyy.length() < 64)
        publickeyy.insert(0, string(64 - publickeyy.length(), '0'));

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", publickeyx + publickeyy));

    return returnMap;
}

map<string, string> ECDSA::createEthAddress(map<string, string> params)
{
    map<string, string> returnMap;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    string publickey;

    if (params.find("public") == params.end())
    {
        publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());
        publickey = ((string)(Converter::integerToString(publicKey.GetPublicElement().x) + Converter::integerToString(publicKey.GetPublicElement().y)));
    }
    else
    {
        publickey = params.at("public");
        if(publickey.length() < 128)
            throw CryptoPP::InvalidArgument("ETH: not a valid eth public key length");
    }

    string publicHash = Hasher::keccak256(publickey);
    if(publicHash.length() < 64)
        publicHash.insert(0, string(64 - publicHash.length(), '0'));

    string address = publicHash.substr(24, 63);

    returnMap.insert(pair<string, string>("address", address));
    return returnMap;
}

map<string, string> ECDSA::exportEthKeys()
{
    map<string, string> returnMap;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

    string publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
    string publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);
    string privatekey = Converter::integerToString(privateKey.GetPrivateExponent());

    if(privatekey.length() < 64)
        privatekey.insert(0, string(64 - privatekey.length(), '0'));
    if(publickeyx.length() < 64)
        publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
    if(publickeyy.length() < 64)
        publickeyy.insert(0, string(64 - publickeyy.length(), '0'));

    returnMap.insert(pair<string, string>("private", privatekey));
    returnMap.insert(pair<string, string>("public", publickeyx + publickeyy));

    return returnMap;
}

map<string, string> ECDSA::importEthKeys(map<string, string> params)
{
    map<string, string> returnMap;
    string privatekey = params.at("private");
    string publickey = params.at("public");
//    publickey = publickey.substr(2);

    if(privatekey.length() < 64)
        throw CryptoPP::InvalidArgument("ETH: not a valid private length");

    KeyPairHex keyPair;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

    privateKey.Initialize(CryptoPP::ASN1::secp256k1(), Converter::stringToInteger(privatekey));

    if(publickey != "")
    {
        if(publickey.length() < 128)
            throw CryptoPP::InvalidArgument("ETH: not a valid public length");
        publicKey.Initialize(CryptoPP::ASN1::secp256k1(), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)),
                                                                             Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));
    }
    else
        privateKey.MakePublicKey(publicKey);

    publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
    privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    string publickeyx = Converter::integerToString(publicKey.GetPublicElement().x);
    string publickeyy = Converter::integerToString(publicKey.GetPublicElement().y);

    if(publickeyx.length() < 64)
        publickeyx.insert(0, string(64 - publickeyx.length(), '0'));
    if(publickeyy.length() < 64)
        publickeyy.insert(0, string(64 - publickeyy.length(), '0'));

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", publickeyx + publickeyy));

    return returnMap;
}

map<string, string> ECDSA::signDataEth(string data, map<string, string> params)
{
    map<string, string>returnMap;
    string type = params.at("type");

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

    string signature;
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(privateKey);
    CryptoPP::AutoSeededRandomPool rng;

    if(type == "string")
        CryptoPP::StringSource ss(data, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));
    else if(type == "tx")
    {
        string encodedTx = Encoder::base64url(data);
        CryptoPP::StringSource ss(encodedTx, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));
    }

    if(signature.length() < 128)
        signature.insert(0, string(128 - signature.length(), '0'));

    returnMap.insert(pair<string, string>("data", data));
    returnMap.insert(pair<string, string>("signature", signature));

    return returnMap;
}

map<string, string> ECDSA::verifySignatureEth(string data, string signature, map<string, string> params)
{
    map<string, string>returnMap;
    string publickey = params.at("public");
    string type = params.at("type");

    if(signature.length() < 128)
        throw CryptoPP::InvalidArgument("ETH: not a valid eth signature length");
    if(publickey.length() < 128)
        throw CryptoPP::InvalidArgument("ETH: not a valid public length");

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

    publicKey.Initialize(CryptoPP::ASN1::secp256k1(), CryptoPP::ECPPoint(Converter::stringToInteger(publickey.substr(0, publickey.length() / 2)), Converter::stringToInteger(publickey.substr(publickey.length() / 2, publickey.length() - 1))));

    string decodedSignature;
    CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

    bool result = false;
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(publicKey);
    if(type == "string")
        CryptoPP::StringSource ss2(decodedSignature + data, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    else if(type == "tx")
    {
        string encodedTx = Encoder::base64url(data);
        CryptoPP::StringSource ss2(decodedSignature + encodedTx, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));
    }

    returnMap.insert(pair<string, string>("data", data));
    returnMap.insert(pair<string, string>("signature", signature));
    returnMap.insert(pair<string, string>("valid", result ? "true" : "false"));

    return returnMap;
}


