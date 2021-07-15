//
//  <nullsaiexception.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "nullsaiexception.h"

NullSaiException::NullSaiException()
{

}

NullSaiException::NullSaiException(QString message)
{
    this->message = message;
}

const char* NullSaiException::what() const throw()
{
    return this->message.toStdString().c_str();
}

QString NullSaiException::whatQ() const throw()
{
    return this->message;
}
