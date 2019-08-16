#ifndef QSIMPLESERVER_H
#define QSIMPLESERVER_H

#include <QtNetwork>
#include <QSqlDatabase>
#include <QSql>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QSqlQueryModel>
#include <QSqlError>
#include <QMap>
#include <QFile>
#include <QString>
#include <QStringList>
#include <QCoreApplication>
#include <QDataStream>
#include <QTime>
#include <QObject>
#include <QSslSocket>
#include <QDateTime>
#include <QByteArray>
#include <QVector>


#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>



class QSimpleServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit QSimpleServer(QObject *parent = nullptr);

    QSslSocket* socket;
    quint16 m_nNextBlockSize;
    QString request;
    QStringList lst;
    QString portTCP;
    QString passwd;
    QMap<QString, QString> map;
    QMap<int, int> srvsMap;  // ассоциативный контейнер с доп. услугами. ключ - услуга, значение - ее цена
    QSqlDatabase db = QSqlDatabase::addDatabase("QMYSQL");
    QSqlQuery query;
    QDateTime now;
    int calls;

    QNetworkAccessManager *manager = new QNetworkAccessManager(this);


    void senderToClient(QSslSocket *socket, const QString &str);
    void incomingConnection(qintptr handle);
    bool readConfig(QStringList &line);
    void queryToSql(const QString &id, const QString& quest, QString& answer);
    void askSql(const QString &ident, const QString& key, QString& answer);
    void updateSql(const QString &id, const QString& key, const QString arg);
    void injectTrustedPay(const QString &id, const QString& key, QString &result);
    bool chekAuth(const QString& id, const QString& pass);
    void showMsgs(const QString &id, QString &result);
    void insertMsg(const QString &id, const QString &txt);


    void scanSwich(const QString& s);

public slots:
    void onReadyRead();
    void onDisconnected();


    void replyFinished(QNetworkReply* reply);
};

#endif // QSIMPLESERVER_H





































