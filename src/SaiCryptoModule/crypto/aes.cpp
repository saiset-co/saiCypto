//
//  <aes.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "aes.h"

AES::AES()
{

}

map<string, string> AES::encrypt(string data, map<string, string> params)
{
    map<string, string> returnMap;
    string secretId = params.at("secret_id");
    string cipher, encodedCipher, encodedIv;

    Key *secretKey = new Key(secretId);

    CryptoPP::AutoSeededRandomPool rng;

    string secretKeyByte;

    CryptoPP::StringSource ss(secretKey->getSecretKey(), true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(secretKeyByte)));
    const byte* secretKeyPtr = reinterpret_cast<const byte*>(secretKeyByte.data());

    CryptoPP::SecByteBlock key(secretKeyPtr, CryptoPP::AES::MAX_KEYLENGTH);

    byte iv[ CryptoPP::AES::BLOCKSIZE ];
    rng.GenerateBlock( iv, sizeof(iv) );

    CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    CryptoPP::StringSource ss1( data, true, new CryptoPP::StreamTransformationFilter( e, new CryptoPP::StringSink( cipher )));

    CryptoPP::StringSource ss2( cipher, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink( encodedCipher ), false));

    CryptoPP::StringSource(iv, sizeof(iv), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedIv), false));

    returnMap.insert(pair<string, string>("data", data));
    returnMap.insert(pair<string, string>("cipher", encodedIv + encodedCipher));
    return returnMap;
}

map<string, string> AES::decrypt(string cipher, map<string, string> params)
{
    map<string, string> returnMap;
    string secretId = params.at("secret_id");
    string data;

    Key *secretKey = new Key(secretId);

    CryptoPP::AutoSeededRandomPool rng;

    string secretKeyByte;

    CryptoPP::StringSource ss(secretKey->getSecretKey(), true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(secretKeyByte)));
    const byte* secretKeyPtr = reinterpret_cast<const byte*>(secretKeyByte.data());

    CryptoPP::SecByteBlock key(secretKeyPtr, CryptoPP::AES::MAX_KEYLENGTH);

    string encodedIv = cipher.substr(0, 32);
    string encodedCipher = cipher.substr(32, cipher.length() - 32);
    string recoveredCipher;
    CryptoPP::StringSource ss5(encodedCipher, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(recoveredCipher)));
    string decodedIv;
    CryptoPP::StringSource ss3(encodedIv, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decodedIv)));
    const byte* ivptr = reinterpret_cast<const byte*>(decodedIv.data());
    CryptoPP::SecByteBlock iv(ivptr, CryptoPP::AES::BLOCKSIZE);

    CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);
    CryptoPP::StringSource ss4( recoveredCipher, true, new CryptoPP::StreamTransformationFilter( d, new CryptoPP::StringSink( data )));

    returnMap.insert(pair<string, string>("data", data));
    returnMap.insert(pair<string, string>("cipher", cipher));
    return returnMap;
}
