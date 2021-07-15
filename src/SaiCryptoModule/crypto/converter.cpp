//
//  <converter.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "converter.h"
#include <stdio.h>
#include <iostream>

Converter::Converter()
{

}

string Converter::integerToString(CryptoPP::Integer integer)
{
    ostringstream ret;

    ret.str("");
    ret << hex << integer;

    string convertedInteger = ret.str();
    convertedInteger = convertedInteger.substr(0, convertedInteger.size() - 1);
    if(convertedInteger.length() % 2 == 1)
        convertedInteger.insert(0, "0");
    return convertedInteger;
}

CryptoPP::Integer Converter::stringToInteger(string str, STRING_TYPE type)
{
    if(type == HEX)
        str = str.insert(0, "0x");

    return CryptoPP::Integer(str.c_str());
}

void Converter::stringHexToByteArray(vector<unsigned char> &bytes, string const& str)
{
    bytes.reserve(str.size() / 2);
    for (string::size_type i = 0, i_end = str.size(); i < i_end; i += 2)
    {
        unsigned byte;
        istringstream hex_byte(str.substr(i, 2));
        hex_byte >> hex >> byte;
        bytes.push_back(static_cast<unsigned char>(byte));
    }
}

void Converter::stringHexToByteArray2(byte *bytes, string const& str)
{
    int j = 0;
    for (string::size_type i = 0, i_end = str.size(); i < i_end; i += 2)
    {
        unsigned byte;
        istringstream hex_byte(str.substr(i, 2));
        hex_byte >> hex >> byte;
        bytes[j] = byte;
        j++;
    }
}

string Converter::ByteArrayToHexString(byte* bytes, size_t len)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for(int i(0); i < len; i++)
        ss << std::setw(2) << static_cast<int>(*bytes++);

    return ss.str();
}

CryptoPP::Integer Converter::secByteBlockToInteger(CryptoPP::SecByteBlock block)
{
    return CryptoPP::Integer(block, block.size());
}
