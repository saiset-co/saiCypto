//
//  <converter.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef CONVERTER_H
#define CONVERTER_H

#include <cryptopp/integer.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <sstream>
#include <iomanip>

using namespace std;

enum STRING_TYPE
{
   HEX, WIF
};

class Converter
{
public:
    Converter();
    static string integerToString(CryptoPP::Integer integer);
    static CryptoPP::Integer stringToInteger(string str, STRING_TYPE type=HEX);
    static CryptoPP::SecByteBlock integerToSecByteBlock(CryptoPP::Integer integer);
    static CryptoPP::Integer secByteBlockToInteger(CryptoPP::SecByteBlock block);
    static void stringHexToByteArray(vector<unsigned char> &bytes, string const& str);
    static void stringHexToByteArray2(byte *bytes, string const& str);
    static string ByteArrayToHexString(byte* bytes, size_t len);
};

#endif // CONVERTER_H
