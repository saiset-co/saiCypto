//
//  <undefinedsaiexception.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "undefinedsaiexception.h"

UndefinedSaiException::UndefinedSaiException()
{

}

UndefinedSaiException::UndefinedSaiException(QString message)
{
    this->message = message;
}

const char* UndefinedSaiException::what() const throw()
{
    return this->message.toStdString().c_str();
}
