//
//  <saihttpserver.cpp>
//  <app/saicryptomodule>
//
//  Created on <24 Jan 2018>.
//  Copyright © 2018 Webmakom. All rights reserved.

#include "saihttpserver.h"
#include "saicrypto.h"

using namespace std;

SaiCrypto *saicrypto;
QHttpServer *server;

void SaiHttpServer::loadSettings()
{
    if(!QFile::exists(QCoreApplication::applicationDirPath() + "/config.ini"))
    {
        QMap<QString, QString> data;
        data.insert("keypath", "");
        data.insert("address", "127.0.0.1");
        data.insert("port", "8080");
        data.insert("callback", "");
        this->saveSettings(data);
    }
    QTextCodec *codec = QTextCodec::codecForName("utf-8");
    QSettings settings(QCoreApplication::applicationDirPath() + "/config.ini", QSettings::IniFormat);
    settings.setIniCodec(codec);
    QString direcotr = QUrl::fromEncoded(settings.value("keypath", "").toString().toUtf8()).toString();
    if(direcotr == "")
    {
        this->keypath = "";
        std::cout << "Keypath is empty. Default keypath folder is app folder" << endl;
    }
    else if(QDir(direcotr).exists())
        this->keypath = direcotr;
    else
    {
        std::cout << "Keypath: " << keypath.toStdString() << "does not exist. Default keypath folder is app folder" << endl;
        this->keypath = "";
    }
    this->address = settings.value("address", "").toString();
    this->port = settings.value("port", "").toString() == "" ? QString::number(8080) : settings.value("port", "").toString();
    this->callback = settings.value("callback", "").toString();
}

void SaiHttpServer::saveSettings(QMap<QString, QString> data)
{
    QTextCodec *codec = QTextCodec::codecForName("utf-8");
    QSettings settings(QCoreApplication::applicationDirPath() + "/config.ini", QSettings::IniFormat);
    settings.setIniCodec(codec);
    settings.setValue("keypath",  QUrl::fromEncoded(data.value("keypath").toUtf8()).toString());
    settings.setValue("address", data.value("address"));
    settings.setValue("port", data.value("port") == "" ? QString::number(8080) : data.value("port"));
    settings.setValue("callback", data.value("callback"));
}

void SaiHttpServer::createHttpServer()
{
    QString addressEth;
    foreach (const QHostAddress &address, QNetworkInterface::allAddresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && address != QHostAddress(QHostAddress::LocalHost))
             addressEth = address.toString();
    }

    server = new QHttpServer(this);
    connect(server, SIGNAL(newRequest(QHttpRequest*, QHttpResponse*)), this, SLOT(handleRequest(QHttpRequest*, QHttpResponse*)));
    if(this->address == "")
    {
        this->address = "127.0.0.1";
        cout << "The stored IP address is empty. " << endl;
        cout << "SaiCryptoModule is running on localhost:" << this->port.toStdString() << endl;
        server->listen(QHostAddress::Any, this->port.toInt());
    }
    else if(this->address == "127.0.0.1")
    {
        cout << "SaiCryptoModule is running on localhost:" << this->port.toStdString() << endl;
        server->listen(QHostAddress::Any, this->port.toInt());
    }
    else if(this->address != addressEth)
    {
        this->address = addressEth;
        cout << "The stored IP address is not equal to the interface ip." << endl;
        cout << "SaiCryptoModule is running on " << addressEth.toStdString() << ":" << this->port.toStdString() << endl;
        server->listen(QHostAddress(addressEth), this->port.toInt());
    }
    else if(this->address == addressEth)
    {
        cout << "SaiCryptoModule is running on " << this->address.toStdString() << ":" << this->port.toStdString() << endl;
        server->listen(QHostAddress(this->address), this->port.toInt());
    }
    else
    {
        cout << "SaiCryptoModule is running on localhost:" << this->port.toStdString() << endl;
        server->listen(QHostAddress::Any, this->port.toInt());
    }
}

SaiHttpServer::SaiHttpServer()
{
    this->loadSettings();
    this->createHttpServer();
}

QString SaiHttpServer::getPathFromRequest()
{
    return this->request->url().path();
}

QString SaiHttpServer::getMethodFromPath(QString path)
{
    return path.remove(0, 1);
}

QUrlQuery SaiHttpServer::getQueryFromRequest()
{
    return QUrlQuery(this->request->url());
}

QMap<QString, QString> SaiHttpServer::getDataFromQuery(QUrlQuery query)
{
    QMap<QString, QString> data;
    QPair<QString, QString> queryItem;

    foreach (queryItem, query.queryItems()) {
     data.insert(queryItem.first, QUrl(queryItem.second).fromPercentEncoding(queryItem.second.toUtf8()));
    }
    return data;
}

QByteArray SaiHttpServer::redirectToMethod(QString method, QMap<QString, QString> data)
{
    QMap<QString, QString> returnedMap;
    QString returnedString;
    this->postable = true;
    this->contenttype = "application/json";

    saicrypto = new SaiCrypto();

    if(method == "create/keys")
    {
        returnedMap = saicrypto->createKeys(data);
    }
    else if(method == "sign")
    {
        returnedMap = saicrypto->signStringByIdOfKeys(data);
    }
    else if(method == "verify")
    {
        returnedMap = saicrypto->verifySignature(data);
    }
    else if(method == "import")
    {
        returnedMap = saicrypto->importKeys(data);
    }
    else if(method == "export")
    {
        returnedMap = saicrypto->exportKeys(data);
    }
    else if(method == "create/keys/secret")
    {
        returnedMap = saicrypto->makeSecretKey(data);
    }
    else if(method == "encrypt")
    {
        returnedMap = saicrypto->encrypt(data);
    }
    else if(method == "decrypt")
    {
        returnedMap = saicrypto->decrypt(data);
    }
    else if(method == "create/btc/keys")
    {
        returnedMap = saicrypto->createBtcKeys(data);
    }
    else if(method == "create/btc/address")
    {
        returnedMap = saicrypto->createBtcAddress(data);
    }
    else if(method == "sign/btc")
    {
        returnedMap = saicrypto->signDataByBtcKeys(data);
    }
    else if(method == "verify/btc")
    {
        returnedMap = saicrypto->verifySignatureBtc(data);
    }
    else if(method == "import/btc")
    {
        returnedMap = saicrypto->importBtcKeys(data);
    }
    else if(method == "export/btc")
    {
        returnedMap = saicrypto->exportBtcKeys(data);
    }
    else if(method == "create/eth/keys")
    {
        returnedMap = saicrypto->createEthKeys(data);
    }
    else if(method == "create/eth/address")
    {
        returnedMap = saicrypto->createEthAddress(data);
    }
    else if(method == "sign/eth")
    {
        returnedMap = saicrypto->signDataByEthKeys(data);
    }
    else if(method == "verify/eth")
    {
        returnedMap = saicrypto->verifySignatureEth(data);
    }
    else if(method == "export/eth")
    {
        returnedMap = saicrypto->exportEthKeys(data);
    }
    else if(method == "import/eth")
    {
        returnedMap = saicrypto->importEthKeys(data);
    }
    else if(method == "hash")
    {
        returnedMap = saicrypto->hash(data);
    }
    else if(method == "")
    {        
        returnedMap.insert("app", "SaiCryptoModule");
        returnedMap.insert("version", VERSION);
        returnedMap.insert("release", RELEASE_DATE);
        returnedMap.insert("status", "OK");
    }
//    else if(method == "api")
//    {
//        QMap<QString, QString> apiroutes;
//        apiroutes.insert("create-keys", "create/keys?method=(rsa,dh,ecdsa,dsa)[&keysize=(1024, 2048, 3072, 7680, 15360)]");
//        apiroutes.insert("sign-message", "sign?id={key.id}&message={message}");
//        apiroutes.insert("verify-signature", "verify?public={key.public}&signature={signature}&message={message}");
//        apiroutes.insert("import-keys", "import?");
//        apiroutes.insert("export-keys", "");
//        apiroutes.insert("create-secret-key", "create/keys/secret");
//        apiroutes.insert("encrypt", "");
//        apiroutes.insert("decrypt", "");
//        apiroutes.insert("create-btc-keys", "");
//        apiroutes.insert("create-btc-address", "");
//        apiroutes.insert("sign-btc-message", "");
//        apiroutes.insert("verify-btc-signature", "");
//        apiroutes.insert("import-btc-keys", "");
//        apiroutes.insert("export-btc-keys", "");
//        apiroutes.insert("create-eth-keys", "");
//        apiroutes.insert("create-eth-address", "");
//        apiroutes.insert("sign-eth-message", "");
//        apiroutes.insert("verify-eth-signature", "");
//        apiroutes.insert("import-eth-keys", "");
//        apiroutes.insert("export-eth-keys", "");
//        returnedMap = ;
//    }
    else if(method == "admin")
    {
        returnedString = this->adminGet();
        this->postable = false;
        this->contenttype = "text/html";
    }
    else if(method == "admin/post")
    {
        returnedString = this->adminPost(data);
        this->postable = false;
        this->contenttype = "text/html";
    }
    else if(method == "config")
    {
        returnedMap.insert("port", this->port);
        returnedMap.insert("keypath", this->keypath);
        returnedMap.insert("callback", this->callback);
        returnedMap.insert("address", this->address);
    }
    else
    {
        returnedMap.insert("error", "INVALID_REQUEST");
    }

    if(returnedMap.size() > 0)
    {
        return this->toJSON(returnedMap);
    }
    else
    {
        return returnedString.toUtf8();
    }
}

void SaiHttpServer::handleRequest(QHttpRequest *req, QHttpResponse *resp)
{
    Q_UNUSED(req);

    this->request = req;
    this->response = resp;
    this->processRequest();
}

void SaiHttpServer::processRequest()
{
    if (this->request->method() == QHttpRequest::HTTP_POST)
    {
        connect(this->request, SIGNAL(data(const QByteArray&)), this, SLOT(processRequestData(const QByteArray&)));
        connect(this->request, SIGNAL(end()), this, SLOT(sendResponse()));
        connect(this->response, SIGNAL(done()), this, SLOT(sendRequest()));
    }
    else if(this->request->method() == QHttpRequest::HTTP_GET)
    {
        connect(this->request, SIGNAL(end()), this, SLOT(sendResponse()));
        connect(this->response, SIGNAL(done()), this, SLOT(sendRequest()));
    }
    else
    {
        QMap<QString, QString> returnMap;
        returnMap.insert("error", "UNUSED_HTTP_METHOD");
        this->responseData = this->toJSON(returnMap);
        connect(this->request, SIGNAL(end()), this, SLOT(sendResponse()));
        connect(this->response, SIGNAL(done()), this, SLOT(sendRequest()));
    }
}

void SaiHttpServer::processRequestData(const QByteArray& requestData)
{
    this->responseData = this->redirectToMethod(this->getMethodFromPath(this->getPathFromRequest()),
                                                     this->getDataFromQuery(QUrlQuery(requestData)));
}

void SaiHttpServer::sendResponse()
{
    if(this->responseData.isEmpty())
        this->responseData = this->redirectToMethod(this->getMethodFromPath(this->getPathFromRequest()),
                                                                this->getDataFromQuery(this->getQueryFromRequest()));
    this->response->setHeader("Access-Control-Allow-Origin", "*");
    this->response->setHeader("Content-Length", QString::number(this->responseData.size()));
    this->response->setHeader("Content-Type", this->contenttype);
    this->response->setHeader("SaiCryptoModule", VERSION);
    this->response->setHeader("Server", "SaiCryptoModule " + VERSION);
    this->response->writeHead(200);
    this->response->end(this->responseData);
}

void SaiHttpServer::emptyResponse()
{
    this->responseData = "";
}

void SaiHttpServer::sendRequest()
{

    QByteArray postData = this->responseData;
    this->emptyResponse();
    if(this->postable && this->callback != "")
    {
        QString requestUrl = this->callback;
        if(!this->callback.contains("http://") && !this->callback.contains("https://"))
            requestUrl.prepend("http://");

    //    QString requestString = "?";
    //    QJsonDocument jsonData = QJsonDocument::fromJson(postData);
    //    QVariantMap variantData = jsonData.toVariant().toMap();
    //    for(auto iter = variantData.constBegin(); iter != variantData.constEnd(); ++iter)
    //    {
    ////        requestString += iter.key() + "=" + iter.value().toString() + "&";
    //        postData.append(iter.key()).append("=").append(iter.value().toString()).append("&");
    //    }
    //    QNetworkRequest request(requestUrl + requestString);
        QNetworkRequest request(requestUrl);
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded;charset=utf-8");
        request.setHeader(QNetworkRequest::ContentLengthHeader, postData.length());
        request.setRawHeader("Accept-Encoding", "deflate,gzip,compress,br,*");

        this->networkReply = this->networkAccessManager.post(request, postData);

        connect(this->networkReply, SIGNAL(finished()), this, SLOT(getReplyFinished()));
    }
}

void SaiHttpServer::getReplyFinished()
{
    cout << "Callback to " << this->networkReply->url().toString().toStdString() << " results with " << this->networkReply->error() << " error. [" << this->networkReply->errorString().toStdString() << "]" << endl;
}

void SaiHttpServer::createDefaultHtml()
{
    if(!QDir(QCoreApplication::applicationDirPath() + "/assets").exists())
        QDir().mkdir(QCoreApplication::applicationDirPath() + "/assets");

    QFile file(QCoreApplication::applicationDirPath() + "/assets/admin.html");
    string html = "<html>"
                  "<head>"
                  "<title>SaiCryptoModule Admin Panel</title>"
                  "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css\" integrity=\"sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb\" crossorigin=\"anonymous\">"
                    "</head>"
                    "<body>"
                      "<header>"
                        "<span style=\"color: rgba(0, 0, 0, 0.3); transition: none; text-align: center; line-height: 98px; border-width: 0px; margin: 0px; padding: 0px; letter-spacing: -3px; font-weight: 700; font-size: 78px;\">SaiCryptoModule</span> Admin Panel"
                      "</header>"
                      "<form action=\"http://{{address}}:{{port}}/admin/post\" method=\"post\" style=\"padding: 10% 20% 20% 20%\">"
                      "<div class=\"form-group\">"
                        "<label for=\"keypath\">Keypath</label>"
                        "<input type=\"text\" class=\"form-control\" name=\"keypath\" id=\"keypath\" value=\"{{keypath}}\" placeholder=\"{{keypath}}\">"
                      "</div>"
                    "<div class=\"form-group\">"
                        "<label for=\"address\">Host address</label>"
                        "<input type=\"text\" class=\"form-control\" name=\"address\" id=\"address\" value=\"{{address}}\" placeholder=\"{{address}}\">"
                      "</div>"
                      "<div class=\"form-group\">"
                        "<label for=\"port\">Host port</label>"
                        "<input type=\"text\" class=\"form-control\" name=\"port\" id=\"port\" value=\"{{port}}\" placeholder=\"{{port}}\">"
                      "</div>"
                      "<div class=\"form-group\">"
                        "<label for=\"port\">Callback</label>"
                        "<input type=\"text\" class=\"form-control\" name=\"callback\" id=\"callback\" value=\"{{callback}}\" placeholder=\"{{callback}}\">"
                      "</div>"
                      "<button type=\"submit\" id=\"sbmt_btn\" class=\"btn btn-primary\">Submit</button>"
                    "</form>"
                      "<script src=\"https://code.jquery.com/jquery-3.2.1.slim.min.js\" integrity=\"sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN\" crossorigin=\"anonymous\"></script>"
                      "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.3/umd/popper.min.js\" integrity=\"sha384-vFJXuSJphROIrBnz7yo7oB41mKfc8JzQZiCq4NCceLEaO4IHwicKwpJf9c9IpFgh\" crossorigin=\"anonymous\"></script>"
                      "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/js/bootstrap.min.js\" integrity=\"sha384-alpBpkh1PFOepccYVYDB4do5UnbKysX5WZXm3XxPqe5iKTfUKjNkCk9SaVuEZflJ\" crossorigin=\"anonymous\"></script>"
                    "<script>"
                    "$(\"#sbmt_btn\").click(function (e) {"
                      "e.preventDefault();"
                      "var $form = $('form');"
                      "$form.attr(\"action\", $form.attr('action') + \"?\" + decodeURIComponent($form.serialize()));"
                      "$form.submit();"
                    "});"
                    "</script>"
                    "</body>"
                    "</html>";
            if(file.open(QIODevice::ReadWrite))
            {
                QTextStream out(&file);
                out << html.c_str() << endl;
        }
}


QString SaiHttpServer::adminGet()
{
    QString templ = "";

    QFile file(QCoreApplication::applicationDirPath() + "/assets/admin.html");
    if(!file.exists())
         this->createDefaultHtml();
    if (file.open(QIODevice::ReadWrite))
    {
       QTextStream in(&file);
       while(!in.atEnd())
       {
           QString line = in.readLine();
           templ += line;
       }
       file.close();
    }

    return this->templateInText(templ);
}

QString SaiHttpServer::adminPost(QMap<QString, QString> data)
{
    this->saveSettings(data);
    this->loadSettings();
//    this->createHttpServer();
    return this->adminGet();
}

QString SaiHttpServer::templateInText(QString templ)
{
    templ.replace(QString("{{keypath}}"), QUrl::fromEncoded(this->keypath.toUtf8()).toString());
    templ.replace(QString("{{address}}"), this->address);
    templ.replace(QString("{{port}}"), this->port);
    templ.replace(QString("{{callback}}"), this->callback);
    return templ;
}

void SaiHttpServer::defaultRequest()
{

}

QByteArray SaiHttpServer::toJSON(QMap<QString, QString> data)
{
    QJsonObject ret;
    QMapIterator<QString, QString> i(data);
    while (i.hasNext()) {
        i.next();
        ret.insert(i.key(), i.value());
    }
    QJsonDocument doc(ret);
    return doc.toJson(QJsonDocument::Indented);
}
