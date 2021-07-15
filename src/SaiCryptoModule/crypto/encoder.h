#ifndef ENCODER_H
#define ENCODER_H

#include <stdio.h>
#include <iostream>
#include <converter.h>

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptlib.h>
#include <cryptopp/base64.h>
#include <osrng.h>

using namespace std;
class Encoder
{
public:
    Encoder();
    static string base58(string data);
    static string fromBase58(string data);
    static string base64url(string data);
};

#endif // ENCODER_H
