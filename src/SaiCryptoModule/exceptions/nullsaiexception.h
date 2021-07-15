//
//  <nullsaiexception.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef NULLSAIEXCEPTION_H
#define NULLSAIEXCEPTION_H

#include <iostream>
#include <exception>
#include <QString>
using namespace std;

class NullSaiException : public exception
{
public:
    QString message;
    NullSaiException();
    NullSaiException(QString message);
    virtual const char* what() const throw();
    QString whatQ() const throw();
};

#endif // NULLSAIEXCEPTION_H
