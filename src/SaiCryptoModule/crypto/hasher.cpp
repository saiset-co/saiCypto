//
//  <hasher.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "hasher.h"

Hasher::Hasher()
{

}

string Hasher::sha256(string data)
{
    vector<byte> bytes;

    Converter::stringHexToByteArray(bytes, data);

    byte digest[ CryptoPP::SHA256::DIGESTSIZE ];

    CryptoPP::SHA256().CalculateDigest(digest, &bytes[0],bytes.size());

    string result = Converter::ByteArrayToHexString(digest, CryptoPP::SHA256::DIGESTSIZE);

    return result;
}

string Hasher::ripemd160(string data)
{
    vector<byte> bytes;

    Converter::stringHexToByteArray(bytes, data);

    byte digest[ CryptoPP::RIPEMD160::DIGESTSIZE ];

    CryptoPP::RIPEMD160().CalculateDigest(digest, &bytes[0],bytes.size());

    string result = Converter::ByteArrayToHexString(digest, CryptoPP::RIPEMD160::DIGESTSIZE);

    return result;
}

string Hasher::keccak256(string data)
{
    byte digest[ CryptoPP::Keccak_256::DIGESTSIZE ];

    CryptoPP::Integer integer = Converter::stringToInteger(data);

    int byteCount=integer.BitCount() / 8;

    if(integer.BitCount() % 8 != 0)
        byteCount++;

    byte *byteArray = new byte[byteCount];
    integer.Encode(byteArray,byteCount);

    CryptoPP::Keccak_256 hash;
    hash.Update(byteArray,byteCount);
    hash.Final(digest);

    CryptoPP::Integer result;
    result.Decode(digest,CryptoPP::Keccak_256::DIGESTSIZE);

    return Converter::integerToString(result);
}
