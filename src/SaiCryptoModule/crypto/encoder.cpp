#include "encoder.h"

Encoder::Encoder()
{

}

string Encoder::base64url(string data)
{
    string encoded;

    CryptoPP::StringSource ss(data, true,
        new CryptoPP::Base64URLEncoder(new CryptoPP::StringSink(encoded)));

    return encoded;
}

string Encoder::fromBase58(string data)
{

}

string Encoder::base58(string data)
{
    string codestring = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    string encoded = "";
    CryptoPP::Integer integer = Converter::stringToInteger(data);
    CryptoPP::Integer remainder;
    CryptoPP::Integer base(58);
    CryptoPP::Integer result;
    while(integer > CryptoPP::Integer::Zero())
    {
        CryptoPP::Integer::Divide(remainder, result, integer, base);
        integer = CryptoPP::Integer(result);
        encoded += codestring[remainder.ConvertToLong()];
    }
    encoded += codestring[0];
    reverse(encoded.begin(), encoded.end());
    return encoded;
}
