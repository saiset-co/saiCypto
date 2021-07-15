//
//  <encryptmethod.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "encryptmethod.h"

EncryptMethod::EncryptMethod()
{

}
map<string, string> EncryptMethod::createKeys(map<string, string> params)
{
    return params;
}

map<string, string> EncryptMethod::signMessage(string message)
{
    message = message;
    return map<string, string>();
}

map<string, string> EncryptMethod::verifySignature(string message, string signature, map<string, string> params)
{
    params.insert(pair<string, string>("message", message));
    params.insert(pair<string, string>("signature", signature));
    return params;
}

map<string, string> EncryptMethod::exportKeys()
{
    return map<string, string>();
}

map<string, string> EncryptMethod::importKeys(map<string, string> params)
{
    return params;
}

map<string, string> EncryptMethod::encrypt(string message, map<string, string> params)
{
    params.insert(pair<string, string>("message", message));
    return params;
}

map<string, string> EncryptMethod::decrypt(string cipher, map<string, string> params)
{
    params.insert(pair<string, string>("cipher", cipher));
    return params;
}

map<string, string> EncryptMethod::makeSecretKey(map<string, string> params)
{
    return params;
}

//string EncryptMethod::base58(string data)
//{
//    size_t output_wpos = 0;

//            __int64 num;
//            int remainder;

//            while (id_num > 0) {

//                num = id_num / 58;
//                remainder = id_num % 58;

//                if (output_wpos < output_len) {
//                    output[output_wpos++] = kLessConfusingChars[remainder];
//                }
//                else {
//                    output[0] = '\0';
//                    return 0;
//                }

//                id_num = num;
//            }

//}
