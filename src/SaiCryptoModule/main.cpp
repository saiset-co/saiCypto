//
//  <main.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include <QCoreApplication>
#include <saihttpserver.h>
using namespace std;

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    cout << "*************************************" << endl;
    SaiHttpServer saihttpserver;
    app.exec();
}
