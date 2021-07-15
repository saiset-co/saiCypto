//
//  <undefinedsaiexception.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#ifndef UNDEFINEDSAIEXCEPTION_H
#define UNDEFINEDSAIEXCEPTION_H

#include <iostream>
#include <exception>
#include <QString>
using namespace std;

class UndefinedSaiException : public exception
{
public:
    QString message;
    UndefinedSaiException();
    UndefinedSaiException(QString message);
    virtual const char* what() const throw();
};

#endif // UNDEFINEDSAIEXCEPTION_H
