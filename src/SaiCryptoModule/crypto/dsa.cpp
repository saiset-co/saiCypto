//
//  <dsa.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "dsa.h"

DSA::DSA()
{
    this->key = new Key();
    this->ENCRYPTMETHOD_NAME = "dsa";
}

DSA::DSA(Key *key)
{
    this->key = key;
    this->ENCRYPTMETHOD_NAME = "dsa";
}

map<string, string> DSA::createKeys(map<string, string> params)
{
    string keysize = params.at("keysize");

    map<string, string> returnMap;

    KeyPairHex keyPair;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::Integer p, g, q;

    int modulusSize = stoi(keysize);
    int primeSize = 0;
    switch (modulusSize)
    {
        case 1024:
            primeSize = 256;
            p = CryptoPP::Integer("0xf99638998fa0e9af9c9717aabc059f5ba865834cd0d1e21367c5fee51d17fe198e2c30a809e3febea5ee0b079cdd59dcfceac3139e8ba379270a1457d9aa6783caf3848da2a310b67c239b398de5aa0ceaa402b5975f05509970eec2fa98816fb934da6b6ff52036797c5569816f1c4bf2ad6a06f154e0936edb75de9242cfcd");
            q = CryptoPP::Integer("0xd42db673925409f06e40a9aad635637480da4161");
            g = CryptoPP::Integer("0x4853a26f043271cf6368f6dde8a990a03a33f088898e2ce8a61a73b5f8cdd334978d8b06f588779102e13f35b733ef2092adb41520a55db81006a9165341bfd4fb744282e15534a22a3905ca7d58919d00bfde8cb518029d7d89ca9752edb762b58c1c4fdb17e6d617972ea4f9a36b96b81b236e09f02b5d59e73b75c2ddf81e");
            break;
        case 2048:
            primeSize = 512;
            p = CryptoPP::Integer("0xe381e4f055a4b0892e02d9fe5653628ccae2485628287100df42467413ab40448f1ee53f1072c5fcb1b389e98a1c812701d2d6a7eb0c49e13e7a0f044215991ebd8a6c6d04752dae09d26b2797a6a8fc336e7ecafff3fc021394aeed8b52c184a57b55de3ec9a3907822795bfbde24e82e1fdf6a83b248f156989b4ac8e85aef8815c83b9fa9e9bf2d03750a12b688fea5199e30cca47e0b045ca1f8e30358d27d04c556628b5590ce9b4a4d67acf1f5965c6ee30fca85f814598f947f573f27fb54684f383354c9b99958b9de53ca51d886893744c40157c63e5d4dd52e88d1637584fb305b5e604e5c68e3cd924a9d242f8ac392c52437eb7ae74a30431621");
            q = CryptoPP::Integer("0xbb143714157387774d1a61693f93fffd514789c09a4b1ce60dfc7277");
            g = CryptoPP::Integer("0x17e584285fab46e39cb2b79c991390ccc9b86fb524b8c85746cf6d87de86e4cf6c4c76ca40b7fa2a79fb7d7e0d3155aa4dade30cd4abbe34d5e3cf6d00159833f32e8f90aa82d599d6249ea7f0845e452fe77d020331070641f5990983078a7fb412e67018d507c2d9c510a51e7969d9db908bacfad5721cb31dace106ee29a254db7fa56e89ff9b4988949eaba07578140943a998efc12086e4bd827806d82698eed1bda3d7485c38ee46f7aa1199e9a8322827313ebb7b2ffeeaee7f9dd1bce6efeae346c68e0c8088c60d5938e36239ed1b905ca320815e904da1c48ce3fbbbb61cc20ff1768e18c25ede3c0e4bfdd2d14560e288f04e0c6139114e71e5f2");
            break;
        case 3072:
            primeSize = 768;
            p = CryptoPP::Integer("0xabb0c423166fc40008fe300762baeeb6cedb5429867271883cffc28b2d9973359ac4a94649f1c1a3a088a8f23013ebe4fa280b5249fc5ebf199dafe10b596e18b9ed4fca94194b2d0ebd6dfae7a53bb68dd7b26a68cf2124cb26c9a72a56c714b7640262d3822eb646db988e196aac6ebacab1a55010ce689ab7514fe6583fd44a226312ed1e4e597e72083dd52671e59c8e68c55e2df5384d1d5dc75d1e674eee7d97d4fbbb5c3804cd20378c05c585283f12f38213f3de94efe37c37438856d5c48a05965a239f23e5f7dea1e86aa34f8d0ef08e492a12132a53842d09cd5d8698fcb52d0cd8125822f00c8ff399b59e3d3a6dd90e6c62f56304a8cae3715000d89ac723572ffdb011db242c3c7f9da76085a43ef96688a88c7eedd68e1d303016b29cf8a7fb005f350248018598c60aed184c7c8a8ceb9f6c208a21799e65e6c90375a679e4ba39a398020951670f11078ad2dec436cf77a35ff9c16ec4e2a9d0597d8eb222513aaff4ee64847826e2122968a28aaca6a9cdde358ec73dfd");
            q = CryptoPP::Integer("0xd1fafbe3290e1230fe0e19b974abfbd3492ee9a73a5e1f1021a9ff1a80b66345");
            g = CryptoPP::Integer("0x7b85ad5182187e53f8cf8e82614470a31d4446f436533dae6eab7782fda7930ae69fee777415a44c31d7d8bbd57bae41c98919938a925e290e39435c3e88174f9e91de26ddedb6d6376c5e0e00c3c88c5f5473f0d5e9e6a2b208952d2f139b2415c5d1b4892d0625fcfd6926e5506c86b14bd2ebc9bb4d5c1ad3c7399f18d4f6800bf899f5550d51624fe45d05cc44615dc39eca42bc2fd36999c1178370d524de01f65a1fd2790252821b4670564132303fdafae9c7894fb07f873f53341f32dfc738763187ac2e81fd440c9460ba91dd7dab935d1f9524aca486950d91653438cffc4dbc5e600f153ed45c25c86c09163a285bfa427f10386f87b353656cdba1a773aa5f626362f8e27755db2d0790d28ae37e2904001040e993319bf174dfa037cffaae6e9bd9b49229945cb6a6e5ee7c8a91c8d76ca1e0e50f9afd2f62af5d6df53688f823dcfb9b2d3562919a1a5b28608e203d67b2a6c449d4e4329cab6740dfe99549295072c125e9ca8865f4d9ea3b3035722767fcb10db479c35b24");
            break;
        default:
            throw CryptoPP::InvalidArgument("DSA: not a valid prime length");
    }

    CryptoPP::DSA::PrivateKey privateKey;
    privateKey.Initialize(rng, p, q, g);

    CryptoPP::DSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);

    publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
    privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

    string publickey = Converter::integerToString(publicKey.GetPublicElement());
    if(static_cast<int>(publickey.length()) < primeSize)
        publickey.insert(0, string(primeSize - static_cast<int>(publickey.length()), '0'));

    this->key->setKeyPair(keyPair);
    this->key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    this->key->save();

    returnMap.insert(pair<string, string>("id", this->key->getKeyId()));
    returnMap.insert(pair<string, string>("public", publickey));

    return returnMap;
}

map<string, string> DSA::signMessage(string message)
{
    map<string, string>returnMap;

    CryptoPP::DSA::PrivateKey privateKey;
    privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

    string signature;
    CryptoPP::DSA::Signer signer(privateKey);
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::StringSource ss(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature), false)));

    returnMap.insert(pair<string, string>("message", message));
    returnMap.insert(pair<string, string>("signature", signature));

    return returnMap;
}

map<string, string> DSA::verifySignature(string message, string signature, map<string, string> params)
{
    string publickey = params.at("public");

    map<string, string>returnMap;

    CryptoPP::DSA::PublicKey publicKey;
    CryptoPP::Integer p, g, q;

    int modulusSize = static_cast<int>(publickey.length());
    int signatureSize = 0;
    switch (modulusSize)
    {
        case 256:
            signatureSize = 80;
            p = CryptoPP::Integer("0xf99638998fa0e9af9c9717aabc059f5ba865834cd0d1e21367c5fee51d17fe198e2c30a809e3febea5ee0b079cdd59dcfceac3139e8ba379270a1457d9aa6783caf3848da2a310b67c239b398de5aa0ceaa402b5975f05509970eec2fa98816fb934da6b6ff52036797c5569816f1c4bf2ad6a06f154e0936edb75de9242cfcd");
            q = CryptoPP::Integer("0xd42db673925409f06e40a9aad635637480da4161");
            g = CryptoPP::Integer("0x4853a26f043271cf6368f6dde8a990a03a33f088898e2ce8a61a73b5f8cdd334978d8b06f588779102e13f35b733ef2092adb41520a55db81006a9165341bfd4fb744282e15534a22a3905ca7d58919d00bfde8cb518029d7d89ca9752edb762b58c1c4fdb17e6d617972ea4f9a36b96b81b236e09f02b5d59e73b75c2ddf81e");
            break;
        case 512:
            signatureSize = 112;
            p = CryptoPP::Integer("0xe381e4f055a4b0892e02d9fe5653628ccae2485628287100df42467413ab40448f1ee53f1072c5fcb1b389e98a1c812701d2d6a7eb0c49e13e7a0f044215991ebd8a6c6d04752dae09d26b2797a6a8fc336e7ecafff3fc021394aeed8b52c184a57b55de3ec9a3907822795bfbde24e82e1fdf6a83b248f156989b4ac8e85aef8815c83b9fa9e9bf2d03750a12b688fea5199e30cca47e0b045ca1f8e30358d27d04c556628b5590ce9b4a4d67acf1f5965c6ee30fca85f814598f947f573f27fb54684f383354c9b99958b9de53ca51d886893744c40157c63e5d4dd52e88d1637584fb305b5e604e5c68e3cd924a9d242f8ac392c52437eb7ae74a30431621");
            q = CryptoPP::Integer("0xbb143714157387774d1a61693f93fffd514789c09a4b1ce60dfc7277");
            g = CryptoPP::Integer("0x17e584285fab46e39cb2b79c991390ccc9b86fb524b8c85746cf6d87de86e4cf6c4c76ca40b7fa2a79fb7d7e0d3155aa4dade30cd4abbe34d5e3cf6d00159833f32e8f90aa82d599d6249ea7f0845e452fe77d020331070641f5990983078a7fb412e67018d507c2d9c510a51e7969d9db908bacfad5721cb31dace106ee29a254db7fa56e89ff9b4988949eaba07578140943a998efc12086e4bd827806d82698eed1bda3d7485c38ee46f7aa1199e9a8322827313ebb7b2ffeeaee7f9dd1bce6efeae346c68e0c8088c60d5938e36239ed1b905ca320815e904da1c48ce3fbbbb61cc20ff1768e18c25ede3c0e4bfdd2d14560e288f04e0c6139114e71e5f2");
            break;
        case 768:
            signatureSize = 128;
            p = CryptoPP::Integer("0xabb0c423166fc40008fe300762baeeb6cedb5429867271883cffc28b2d9973359ac4a94649f1c1a3a088a8f23013ebe4fa280b5249fc5ebf199dafe10b596e18b9ed4fca94194b2d0ebd6dfae7a53bb68dd7b26a68cf2124cb26c9a72a56c714b7640262d3822eb646db988e196aac6ebacab1a55010ce689ab7514fe6583fd44a226312ed1e4e597e72083dd52671e59c8e68c55e2df5384d1d5dc75d1e674eee7d97d4fbbb5c3804cd20378c05c585283f12f38213f3de94efe37c37438856d5c48a05965a239f23e5f7dea1e86aa34f8d0ef08e492a12132a53842d09cd5d8698fcb52d0cd8125822f00c8ff399b59e3d3a6dd90e6c62f56304a8cae3715000d89ac723572ffdb011db242c3c7f9da76085a43ef96688a88c7eedd68e1d303016b29cf8a7fb005f350248018598c60aed184c7c8a8ceb9f6c208a21799e65e6c90375a679e4ba39a398020951670f11078ad2dec436cf77a35ff9c16ec4e2a9d0597d8eb222513aaff4ee64847826e2122968a28aaca6a9cdde358ec73dfd");
            q = CryptoPP::Integer("0xd1fafbe3290e1230fe0e19b974abfbd3492ee9a73a5e1f1021a9ff1a80b66345");
            g = CryptoPP::Integer("0x7b85ad5182187e53f8cf8e82614470a31d4446f436533dae6eab7782fda7930ae69fee777415a44c31d7d8bbd57bae41c98919938a925e290e39435c3e88174f9e91de26ddedb6d6376c5e0e00c3c88c5f5473f0d5e9e6a2b208952d2f139b2415c5d1b4892d0625fcfd6926e5506c86b14bd2ebc9bb4d5c1ad3c7399f18d4f6800bf899f5550d51624fe45d05cc44615dc39eca42bc2fd36999c1178370d524de01f65a1fd2790252821b4670564132303fdafae9c7894fb07f873f53341f32dfc738763187ac2e81fd440c9460ba91dd7dab935d1f9524aca486950d91653438cffc4dbc5e600f153ed45c25c86c09163a285bfa427f10386f87b353656cdba1a773aa5f626362f8e27755db2d0790d28ae37e2904001040e993319bf174dfa037cffaae6e9bd9b49229945cb6a6e5ee7c8a91c8d76ca1e0e50f9afd2f62af5d6df53688f823dcfb9b2d3562919a1a5b28608e203d67b2a6c449d4e4329cab6740dfe99549295072c125e9ca8865f4d9ea3b3035722767fcb10db479c35b24");
            break;
        default:
            throw CryptoPP::InvalidArgument("DSA: not a valid prime length");
    }

    if(static_cast<int>(signature.length()) < signatureSize)
        throw CryptoPP::InvalidArgument("DSA: not a valid signature length");

    publicKey.Initialize(p, q, g, Converter::stringToInteger(publickey));
    string decodedSignature;
    CryptoPP::StringSource ss(signature, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedSignature)));

    bool result = false;
    CryptoPP::DSA::Verifier verifier(publicKey);

    CryptoPP::StringSource ss2(decodedSignature + message, true, new CryptoPP::SignatureVerificationFilter(verifier, new CryptoPP::ArraySink((byte*)&result, sizeof(result))));

    returnMap.insert(pair<string, string>("valid", result ? "true" : "false"));

    return returnMap;
}

map<string, string> DSA::exportKeys()
{
    map<string, string>returnMap;

    CryptoPP::DSA::PrivateKey privateKey;
    privateKey.Load(CryptoPP::StringSource(this->key->getPrivateKey(), true, new CryptoPP::HexDecoder()).Ref());

    CryptoPP::DSA::PublicKey publicKey;
    publicKey.Load(CryptoPP::StringSource(this->key->getPublicKey(), true, new CryptoPP::HexDecoder()).Ref());

    string privatekey = Converter::integerToString(privateKey.GetPrivateExponent());
    string publickey = Converter::integerToString(publicKey.GetPublicElement());

    int primeSize = 0;
    primeSize = static_cast<int>(publickey.length());

    if(primeSize != 256 && primeSize != 512 && primeSize != 768)
    {
        if(primeSize > 0 && primeSize < 256)
            publickey.insert(0, string(256 - primeSize, '0'));
        else if(primeSize > 256 && primeSize < 512)
            publickey.insert(0, string(512 - primeSize, '0'));
        else if(primeSize > 512 && primeSize < 768)
            publickey.insert(0, string(768 - primeSize, '0'));
        else
            throw CryptoPP::InvalidArgument("DSA: Invalid public length");
    }

    returnMap.insert(pair<string, string>("private", privatekey));
    returnMap.insert(pair<string, string>("public", publickey));

    return returnMap;
}

map<string, string> DSA::importKeys(map<string, string> params)
{
    string publickey = params.at("public");
    string privatekey = params.at("private");

    map<string, string>returnMap;

    KeyPairHex keyPair;
    CryptoPP::Integer p, g, q;

    int modulusSize = static_cast<int>(publickey.length());
    switch (modulusSize)
    {
        case 256:
            p = CryptoPP::Integer("0xf99638998fa0e9af9c9717aabc059f5ba865834cd0d1e21367c5fee51d17fe198e2c30a809e3febea5ee0b079cdd59dcfceac3139e8ba379270a1457d9aa6783caf3848da2a310b67c239b398de5aa0ceaa402b5975f05509970eec2fa98816fb934da6b6ff52036797c5569816f1c4bf2ad6a06f154e0936edb75de9242cfcd");
            q = CryptoPP::Integer("0xd42db673925409f06e40a9aad635637480da4161");
            g = CryptoPP::Integer("0x4853a26f043271cf6368f6dde8a990a03a33f088898e2ce8a61a73b5f8cdd334978d8b06f588779102e13f35b733ef2092adb41520a55db81006a9165341bfd4fb744282e15534a22a3905ca7d58919d00bfde8cb518029d7d89ca9752edb762b58c1c4fdb17e6d617972ea4f9a36b96b81b236e09f02b5d59e73b75c2ddf81e");
            break;
        case 512:
            p = CryptoPP::Integer("0xe381e4f055a4b0892e02d9fe5653628ccae2485628287100df42467413ab40448f1ee53f1072c5fcb1b389e98a1c812701d2d6a7eb0c49e13e7a0f044215991ebd8a6c6d04752dae09d26b2797a6a8fc336e7ecafff3fc021394aeed8b52c184a57b55de3ec9a3907822795bfbde24e82e1fdf6a83b248f156989b4ac8e85aef8815c83b9fa9e9bf2d03750a12b688fea5199e30cca47e0b045ca1f8e30358d27d04c556628b5590ce9b4a4d67acf1f5965c6ee30fca85f814598f947f573f27fb54684f383354c9b99958b9de53ca51d886893744c40157c63e5d4dd52e88d1637584fb305b5e604e5c68e3cd924a9d242f8ac392c52437eb7ae74a30431621");
            q = CryptoPP::Integer("0xbb143714157387774d1a61693f93fffd514789c09a4b1ce60dfc7277");
            g = CryptoPP::Integer("0x17e584285fab46e39cb2b79c991390ccc9b86fb524b8c85746cf6d87de86e4cf6c4c76ca40b7fa2a79fb7d7e0d3155aa4dade30cd4abbe34d5e3cf6d00159833f32e8f90aa82d599d6249ea7f0845e452fe77d020331070641f5990983078a7fb412e67018d507c2d9c510a51e7969d9db908bacfad5721cb31dace106ee29a254db7fa56e89ff9b4988949eaba07578140943a998efc12086e4bd827806d82698eed1bda3d7485c38ee46f7aa1199e9a8322827313ebb7b2ffeeaee7f9dd1bce6efeae346c68e0c8088c60d5938e36239ed1b905ca320815e904da1c48ce3fbbbb61cc20ff1768e18c25ede3c0e4bfdd2d14560e288f04e0c6139114e71e5f2");
            break;
        case 768:
            p = CryptoPP::Integer("0xabb0c423166fc40008fe300762baeeb6cedb5429867271883cffc28b2d9973359ac4a94649f1c1a3a088a8f23013ebe4fa280b5249fc5ebf199dafe10b596e18b9ed4fca94194b2d0ebd6dfae7a53bb68dd7b26a68cf2124cb26c9a72a56c714b7640262d3822eb646db988e196aac6ebacab1a55010ce689ab7514fe6583fd44a226312ed1e4e597e72083dd52671e59c8e68c55e2df5384d1d5dc75d1e674eee7d97d4fbbb5c3804cd20378c05c585283f12f38213f3de94efe37c37438856d5c48a05965a239f23e5f7dea1e86aa34f8d0ef08e492a12132a53842d09cd5d8698fcb52d0cd8125822f00c8ff399b59e3d3a6dd90e6c62f56304a8cae3715000d89ac723572ffdb011db242c3c7f9da76085a43ef96688a88c7eedd68e1d303016b29cf8a7fb005f350248018598c60aed184c7c8a8ceb9f6c208a21799e65e6c90375a679e4ba39a398020951670f11078ad2dec436cf77a35ff9c16ec4e2a9d0597d8eb222513aaff4ee64847826e2122968a28aaca6a9cdde358ec73dfd");
            q = CryptoPP::Integer("0xd1fafbe3290e1230fe0e19b974abfbd3492ee9a73a5e1f1021a9ff1a80b66345");
            g = CryptoPP::Integer("0x7b85ad5182187e53f8cf8e82614470a31d4446f436533dae6eab7782fda7930ae69fee777415a44c31d7d8bbd57bae41c98919938a925e290e39435c3e88174f9e91de26ddedb6d6376c5e0e00c3c88c5f5473f0d5e9e6a2b208952d2f139b2415c5d1b4892d0625fcfd6926e5506c86b14bd2ebc9bb4d5c1ad3c7399f18d4f6800bf899f5550d51624fe45d05cc44615dc39eca42bc2fd36999c1178370d524de01f65a1fd2790252821b4670564132303fdafae9c7894fb07f873f53341f32dfc738763187ac2e81fd440c9460ba91dd7dab935d1f9524aca486950d91653438cffc4dbc5e600f153ed45c25c86c09163a285bfa427f10386f87b353656cdba1a773aa5f626362f8e27755db2d0790d28ae37e2904001040e993319bf174dfa037cffaae6e9bd9b49229945cb6a6e5ee7c8a91c8d76ca1e0e50f9afd2f62af5d6df53688f823dcfb9b2d3562919a1a5b28608e203d67b2a6c449d4e4329cab6740dfe99549295072c125e9ca8865f4d9ea3b3035722767fcb10db479c35b24");
            break;
        default:
            throw CryptoPP::InvalidArgument("DSA: not a valid prime length");
    }

    CryptoPP::DSA::PublicKey publicKey;
    publicKey.Initialize(p, q, g, Converter::stringToInteger(publickey));

    CryptoPP::DSA::PrivateKey privateKey;
    privateKey.Initialize(p, q, g, Converter::stringToInteger(privatekey));

    publicKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.publicKey)).Ref());
    privateKey.Save(CryptoPP::HexEncoder(new CryptoPP::StringSink(keyPair.privateKey)).Ref());

    Key *key = new Key();
    key->setKeyPair(keyPair);
    key->setEncryptionMethodName(this->ENCRYPTMETHOD_NAME);
    key->save();

    returnMap.insert(pair<string, string>("id", key->getKeyId()));
    returnMap.insert(pair<string, string>("public", Converter::integerToString(publicKey.GetPublicElement())));

    return returnMap;
}
