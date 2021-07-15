//
//  <hasher.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef HASHER_H
#define HASHER_H

#include <stdio.h>
#include <iostream>
#include <converter.h>

//#include <cryptopp/filters.h>
//#include <cryptopp/hex.h>
#include <cryptlib.h>
#include <cryptopp/keccak.h>
#include <cryptopp/base64.h>
#include <ripemd.h>
#include <osrng.h>
#include <pssr.h>
#include <whrlpool.h>

using namespace std;

class Hasher
{
public:
    Hasher();
    static string sha256(string data);
    static string ripemd160(string data);
    static string keccak256(string data);
};

#endif // HASHER_H
