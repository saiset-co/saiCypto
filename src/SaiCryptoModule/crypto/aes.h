//
//  <aes.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef AES_H
#define AES_H

#include <encryptmethod.h>


class AES : public EncryptMethod
{
public:
    AES();
    map<string, string> encrypt(string data, map<string, string> params);
    map<string, string> decrypt(string cipher, map<string, string> params);
};

#endif // AES_H
