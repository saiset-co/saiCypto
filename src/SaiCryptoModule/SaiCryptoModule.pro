#
#  <saicryptomodule.pro>
#  <app/saicryptomodule>
#
#  Created on <24 Jan 2018>.
#  Copyright © 2018 Webmakom. All rights reserved.

TARGET = SaiCryptoModule

#TEMPLATE = lib

QT += network
QT -= gui

CONFIG += console c++11

INCLUDEPATH += ../src
INCLUDEPATH += ../src/cryptopp
INCLUDEPATH += exceptions
INCLUDEPATH += crypto


LIBS += -L../lib
LIBS += -lqhttpserver
win32 {
    CONFIG += static
    LIBS += -L../lib -lcryptlib
} else {
    LIBS += -L../lib -lcryptopp
}

macx {
    PRE_TARGETDEPS += ../lib/libcryptopp.dylib
    MY.path = Contents/Frameworks
    MY.files = ../lib/libcryptopp.dylib
    QMAKE_BUNDLE_DATA += MY
}

#win32 {
#    release {
#        DESTDIR = deploy
#        QMAKE_POST_LINK += windeployqt $$OUT_PWD/$$DESTDIR
#    }
#}

SOURCES += main.cpp \
    saihttpserver.cpp \
    saicrypto.cpp \
    exceptions/nullsaiexception.cpp \
    exceptions/undefinedsaiexception.cpp \
    crypto/rsa.cpp \
    crypto/dsa.cpp \
    crypto/ecdsa.cpp \
    crypto/encryptmethod.cpp \
    crypto/converter.cpp \
    crypto/hasher.cpp \
    crypto/dh.cpp \
    crypto/aes.cpp \
    crypto/key.cpp \
    crypto/encoder.cpp \
    crypto/ecdh.cpp

HEADERS += \
    saihttpserver.h \
    saicrypto.h \    
    exceptions/nullsaiexception.h \
    exceptions/undefinedsaiexception.h \
    crypto/rsa.h \
    crypto/dsa.h \
    crypto/ecdsa.h \
    crypto/encryptmethod.h \
    crypto/converter.h \
    crypto/hasher.h \
    crypto/dh.h \
    crypto/aes.h \
    crypto/key.h \
    crypto/encoder.h \
    crypto/ecdh.h
