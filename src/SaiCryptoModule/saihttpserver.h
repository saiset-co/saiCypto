//
//  <saihttpserver.h>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "qhttpserverfwd.h"
#include <iostream>
#include <QTimer>
#include <QEventLoop>

#include <QObject>
#include <QUrlQuery>
#include <QMetaObject>
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonArray>
#include <QFile>
#include <QMap>
#include <QSettings>
#include <QNetworkAccessManager>
#include <QNetworkInterface>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QHttpMultiPart>
#include <QHttpPart>
#include <QVariantMap>
#include <QVariant>
#include <QTextCodec>
#include <QCoreApplication>

#include <qhttpserver.h>
#include <qhttprequest.h>
#include <qhttpresponse.h>

const QString VERSION = "1.0.7";
const QString RELEASE_DATE = "01.02.2018";

class SaiHttpServer : public QObject
{
    Q_OBJECT

public:
    SaiHttpServer();
private:
    QString port;
    QString address;
    QString keypath;
    QString callback;
    bool postable;
    QString contenttype;
    QNetworkAccessManager networkAccessManager;
    QNetworkReply *networkReply;
    QHttpRequest *request;
    QHttpResponse *response;
    QByteArray responseData;

private slots:
    void loadSettings();
    void saveSettings(QMap<QString, QString> data);
    void createHttpServer();
    void handleRequest(QHttpRequest *req, QHttpResponse *resp);
    void processRequest();
    void processRequestData(const QByteArray& requestData);
    void sendResponse();
    void sendRequest();
    void emptyResponse();
    void getReplyFinished();
    QString getPathFromRequest();
    QString getMethodFromPath(QString path);
    QUrlQuery getQueryFromRequest();
    QMap<QString, QString> getDataFromQuery(QUrlQuery query);
    QByteArray redirectToMethod(QString method, QMap<QString, QString> data);
    void createDefaultHtml();
    QString adminGet();
    QString adminPost(QMap<QString, QString> data);
    QString templateInText(QString templ);
    void defaultRequest();
    QByteArray toJSON(QMap<QString, QString> data);
};
