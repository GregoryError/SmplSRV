#include "qsimpleserver.h"
#include <iostream>

QSimpleServer::QSimpleServer(QObject *parent) :
    QTcpServer(parent)
{
    QDateTime now = QDateTime::currentDateTime();
    calls = 0;

    qDebug() << "Check the current time...." << now.toString("dd.MM.yyyy hh:mm");

    //--------------srvs-file----------------------------------------------------------

    QVector<int> srvsVal;
    QFile s_in("srvs");
    if (!s_in.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << s_in.errorString() + '\n';
        qDebug() << "Error: can`t open 'srvs' file. Check the location.\nServer is working anyway.";
    }
    else {
        qDebug() << "Open the 'srvs' file.... ok";
        while (!s_in.atEnd()) {
            QString valTmp = s_in.readLine();
            QString pVal;
            for (auto &a : valTmp)
            {
                if (a == '#')
                    break;
                pVal += a;
            }
            srvsVal.push_back(pVal.toInt());
        }

        for (int i = 0; i < srvsVal.size() - 1; i += 2)
        {
            // qDebug() << "Key: " << srvsVal[i] << ", Val: " << srvsVal[i + 1];
            srvsMap.insert(srvsVal[i], srvsVal[i + 1]);
        }
    }
    s_in.close();

    //--------------config-data------------------------------------------------------

    bool record;
    if (readConfig(lst))
        record = true;
    else record = false;

    QString hostSQL = lst[4];     // SQL connectivity data
    QString usrNameSQL = lst[5];
    QString passSQL = lst[6];
    QString portSQL = lst[7];
    QString nameSQL = lst[8];
    portTCP = lst[13];            // TCP settings

    //----------------------SQL------------------------------------------------------

    db.setHostName(hostSQL);
    db.setUserName(usrNameSQL);
    db.setPassword(passSQL);
    db.setPort(portSQL.toInt());
    db.setDatabaseName(nameSQL);
    db.setConnectOptions("MYSQL_OPT_RECONNECT=TRUE;");

    if (!db.open() ) {
        qDebug() << QTime::currentTime().toString() + " " + db.lastError().text();
        qDebug() << "Available drivers: ";
        QStringList lst = db.drivers();
        for (auto &c:lst)
        {
            qDebug() << c;
        }
    }else {
        //     QStringList lst = db.drivers();
        //     foreach (QString str, lst) {
        //     qDebug() << QTime::currentTime().toString() + ": " + str;
        // }

        qDebug() << "Connect to database.... ok";
    }

    //----------------------PATTERNS-------------------------------------------------

    if (record) {
        int i = 25;  // from line 25 begin patterns
        while (lst[i] != "end")
        {
            QString temp(lst[i]);
            QString key;
            QString val;
            for (const auto &c: temp)
            {
                key += c;
                if (c == ':' || c == '!')
                    break;

            }

            val = temp.mid(key.length(), temp.length() - key.length());
            map.insert(key, val);
            // qDebug() << "Recorded patterns: " + key + " == " + val;
            ++i;
        }
    }else
        qDebug() << "Can`t make a command set";

    //----------------------TCP-SERVER-----------------------------------------------

    if (listen(QHostAddress::Any, static_cast<quint16>(portTCP.toInt())))
        qDebug() << "Listening port " << portTCP.toInt() << "...";
    else qDebug() << "Error while starting: " + errorString();

    connect(manager, SIGNAL(finished(QNetworkReply*)),
            this, SLOT(replyFinished(QNetworkReply*)));
}

void QSimpleServer::senderToClient(QSslSocket *socket, const QString &str)
{
    QByteArray arrBlock;
    QDataStream out(&arrBlock, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_11);
    out << quint16(0) << str;
    out.device()->seek(0);
    out << quint16(static_cast<unsigned long>(arrBlock.size()) - sizeof(quint16));
    socket->write(arrBlock);
}

void QSimpleServer::incomingConnection(qintptr handle)
{
    socket = new QSslSocket();

    if (!socket->setSocketDescriptor(handle)){
        qDebug() << errorString();
        return;
    }
    const QString serverCertPath("server.crt");
    const QString serverKeyPath("server.key");
    socket->setLocalCertificate(serverCertPath);
    socket->setPrivateKey(serverKeyPath, QSsl::Rsa, QSsl::Pem, "test");
    socket->startServerEncryption();

    qDebug() << "waiting for encryption...";

    if (!socket->waitForEncrypted())
    {
        qDebug() << QDate::currentDate().toString("dd.MM.yy")
                    + ", " + QTime::currentTime().toString()
                    + ": " + socket->peerAddress().toString() + "   " + socket->errorString();
        //        qDebug() << socket->errorString();
        return;
    }

    qDebug() << "Connection is encrypted.";

    connect(socket, SIGNAL(readyRead()), this, SLOT(onReadyRead()));
    connect(socket, SIGNAL(disconnected()), this, SLOT(onDisconnected()));

}

void QSimpleServer::onReadyRead()
{
    QSslSocket* socket = qobject_cast<QSslSocket*> (sender());

    //QString message;
    //
    //QDataStream in(socket);
    //in.setVersion(QDataStream::Qt_5_9);
    //
    //for (;;)
    //{
    //    if (!m_nNextBlockSize)
    //    {
    //        if (socket->bytesAvailable() < sizeof(quint16))
    //        {
    //            break;
    //        }
    //        in >> m_nNextBlockSize;
    //    }
    //    if (socket->bytesAvailable() < m_nNextBlockSize)
    //    {
    //        break;
    //    }
    //    in >> message;
    //
    //    m_nNextBlockSize = 0;
    //}

    ++calls;

    QString message(socket->readAll());

    if (message.mid(0, 6) == "master")
    {
        scanSwich(message.mid(6));
    }

    //socket->close();

    //qDebug() << message;

    QString authData;

    for(auto &c:message)
    {
        if (c == ')')
            break;
        if (c != '(')
            authData += c;
    }

    QString id, pass;

    for (auto &c:authData)
    {
        if (c == '#')
        {
            auto logLen = id.length() + 1;
            pass = authData.mid(logLen, authData.length() - logLen);
            break;
        }
        id += c;
    }

    QString key;

    auto keySince = authData.length() + 2;

    QString onlyQuestion = message.mid(keySince);

    for (auto &c:onlyQuestion)
    {
        key += c;
        if (c == '!' || c == ':')
            break;
    }

    QString attribute = onlyQuestion.mid(key.length());

    // Now we have strings: 'id', 'pass', 'key', and possibly, 'attribute'

    // qDebug() << id;
    // qDebug() << pass;
    // qDebug() << key;
    // qDebug() << attribute;

    QString answ;

    if (chekAuth(id, pass))
    {

        QString result;

        if (key.mid(0, 7) == "setMsgs")
        {
            insertMsg(id, attribute);
        }
        else if (key.mid(0, 10) == "askForMsgs")
        {
            showMsgs(id, answ);
        }
        else if (key.mid(0, 17) == "requestTrustedPay")
        {
            injectTrustedPay(id, key, answ);
        }
        else if(key.mid(0, 4) == "show")
        {
            queryToSql(attribute, key, answ);
        }
        else if(key.mid(0, 3) == "set")
            updateSql(id, key, attribute);
        else if(key.mid(0, 3) == "ask")
        {
            if(key.mid(0, 12) == "askPayments!")
            {
                askSql(id, key, answ);
                //preparePayTable(answ);

            }
            else askSql(id, key, answ);

        }
        else queryToSql(id, key, answ);

        if(key.mid(0, 11) == "getAllData!")
        {
            QString planName;
            short i(0);
            for (auto& c:answ)
            {
                if(c == ' ')
                    ++i;
                if(i == 4 && c != ' ')
                    planName += c;
            }

            QString planStr;

            queryToSql(planName, "showPlan:", planStr);

            i = 0;

            for (auto &c:answ)
            {
                result += c;
                if (c == ' ')
                    ++i;
                if (i == 4)
                {
                    result += planStr;
                    break;
                }
            }
        }
        else result = answ;

        qDebug() << QDate::currentDate().toString("dd.MM.yy")
                    + ", " + QTime::currentTime().toString()
                    + ": id# " + id + " from " + socket->peerAddress().toString() + " asking:   " + key;

        if (key == "getAllData!")
        {
            now = QDateTime::currentDateTime();                                                              //  "07.10.2018|21:52"
            senderToClient(socket, (key + now.toString("dd.MM.yyyy|hh:mm") + result).toUtf8());
        }
        else if (!result.isEmpty())                           // Can put here another option for adjusting possibility
            senderToClient(socket, (key + result).toUtf8());

        //socket->write((key + result).toUtf8());
        //socket->waitForBytesWritten();
        socket->disconnectFromHost();
        // socket->close();
        // socket->deleteLater();

    }
    else
    {
        senderToClient(socket, "denied");

        socket->disconnectFromHost();
    }

    qDebug() << "Overall connections were committed: " << calls;

}

void QSimpleServer::injectTrustedPay(const QString &id, const QString &key, QString &result)
{
    QString t_quest = map.value(key);

    //qDebug() << t_quest;

    QString quest, cash;

    QString payDate_f, payDate;                 // узнаем дату платежа в текущем мсц, и переводим ее в unixtime

    queryToSql(id, "askPayDate!", payDate_f);

    for (auto &ch: payDate_f)
        if (ch.isDigit())
            payDate += ch;

    if (payDate == "0")
        payDate = "1";

    if (payDate.length() == 1)
    {
        QString tmp = payDate;
        payDate = "0" + tmp;
    }

    now = QDateTime::currentDateTime();

    QString dateFirst = now.toString(payDate + "/MM/yyyy");   // dd/MM/yyyy

    // расчетная дата с сегодняшним месяцем это dateFirst

    QDateTime t_Date = QDateTime::fromString(dateFirst, "dd/MM/yyyy");

    // возвращаем ее обратно к типу QDateTime это t_Date

    unsigned long dateSinceInt = t_Date.toTime_t();

    // получаем в integer, UNIX timestamp

    dateFirst = QString::number(t_Date.toTime_t());

    // это строка с тем же UNIX timestamp

    const int month = 2629743; // секунд в месяце

    const int days_3 = 259200;

    // Имеем:
    // dateFirst - строка с timestamp (расчетная дата в текущий месяц)
    // dateSinceInt - целочисленное значение ее же
    // month - кол-во секунд в месяце
    //

    QString dateTill; // время ДО которого будет проверка

    if (now.toTime_t() < dateSinceInt)   //(now.toString("dd").toInt() < payDate.toInt()) // Если сегодняшний день меньше даты платежа
    {
        dateSinceInt -= month;       // уменьшаем время на месяц (Будет начальное время)
        dateTill = dateFirst;        // Конечное время dateTill
        dateFirst = QString::number(dateSinceInt);
        //qDebug() << "Option if: " << "dateFirst: " << dateFirst << "dateTill:" << dateTill;
    }else{
        dateSinceInt += month;
        dateTill = QString::number(dateSinceInt);
        //qDebug() << "Option else: " << "dateFirst: " << dateFirst << "dateTill:" << dateTill;
    }

    // chekForTrustedPay! - is the key for checking is it possible to take trusted pay
    // its content: SELECT * FROM pays WHERE mid = AND time BETWEEN AND type IN (20,21,22)

    QString checkStr(map.value("chekForTrustedPay!"));

    QString checkQuest;

    for (auto &ch:checkStr)
    {
        checkQuest += ch;
        if (checkQuest.right(7) == "BETWEEN")
        {
            checkQuest += " ";
            checkQuest += dateFirst + " AND " + QString::number((days_3 + dateTill.toInt()));
        }

        if (checkQuest.right(1) == '=')
        {
            checkQuest += " " + id;
        }
    }

    //qDebug() << "CheckQuest: " << checkQuest;

    query.exec(checkQuest);

    qDebug() << "DEBUG INFO: Trusted_check_query = " << checkQuest;

    QSqlRecord payRec = query.record();

    if (query.size() > 0)
    {
        query.first();
        // qDebug() << "Content of query (cash): " <<  query.value(payRec.indexOf("cash")).toInt();
    }

    if (query.size() > 0)
    {
        qDebug() << "Trusted_pay denied for " << id;
        result = "PayDenied";
        return;
    }
    else
    {
        qDebug() << "Allowed to take a trusted_pay for " << id;

        int PaySumm = 0;

        query.exec(map.value("showPlanPrice!") + " id=" + id + ")");

        payRec = query.record();

        while(query.next())
            PaySumm = query.value(payRec.indexOf("price")).toInt();

        // Additional services:

        query.exec(map.value("showUserSrvs!") + " id=" + id);

        payRec = query.record();

        int srvsNum = 0;

        while(query.next())
            srvsNum = query.value(payRec.indexOf("srvs")).toInt();

        if (srvsNum != 0)
        {
            const int BITS_PER_INT = sizeof (int) * CHAR_BIT;

            int test_bit = 1;

            for (int i = 0; i != BITS_PER_INT; ++i, test_bit <<= 1)
                PaySumm += srvsMap.value(srvsNum & test_bit ? test_bit : 0, 0);

        }

        now = QDateTime::currentDateTime();

        query.exec(map.value("requestTrustedPay!")
                   .arg(id)     // (mid, cash, type, time, coment, category, bonus) VALUES (%1, %2, %3, %4, %5, %6, %7)
                   .arg(PaySumm)
                   .arg(21)
                   .arg(now.currentDateTime().toSecsSinceEpoch() + days_3)
                   .arg("'Платеж создан " + now.currentDateTime().toString("dd.MM.yyyy hh:mm") + " через мобильное приложение. '")
                   .arg("'Платеж создан " + now.currentDateTime().toString("dd.MM.yyyy hh:mm") + " через мобильное приложение. '")
                   .arg(1000)
                   .arg("'y'"));

        //        pushTmpPay!UPDATE users SET balance=balance+%1, state='on' WHERE id=%2

        query.exec(map.value("pushTmpPay!").arg(PaySumm).arg(id));

        result = "PayOk";  // посылаем на устройство сообщение что все ок, запрос выполнен
    }

    // Cash:
    // showPlanPrice!   =     SELECT price FROM plans2 WHERE id=(SELECT paket FROM users WHERE           ///(330)
    // showUserSrvs!     =      SELECT srvs FROM users WHERE id=23341  (3)
    // INSERT INTO pays (mid, cash, type, time, admin_id, admin_ip, office, bonus, reason, coment, category)
    // VALUES (a, b, c, d, e, f, g, h, i, j, k)
}

void QSimpleServer::showMsgs(const QString &id, QString &result)
{
    //showAdminMsgs! = SELECT coment, time FROM pays WHERE mid = %1 AND type = 30 AND category IN (493) ORDER BY time DESC
    //showUserMsgs! = SELECT reason, time FROM pays WHERE mid = %1 AND type = 30 AND category IN (491) ORDER BY time DESC

    query.exec(map.value("showAdminMsgs!").arg(id));

    QString adminMsg, userMsg;

    QSqlRecord msgRec = query.record();

    while (query.next())
    {
        adminMsg += query.value(msgRec.indexOf("coment")).toString() + "~time:";
        adminMsg += query.value(msgRec.indexOf("time")).toString() + "~end()";
    }

    query.exec(map.value("showUserMsgs!").arg(id));

    msgRec = query.record();

    while (query.next())
    {
        userMsg += query.value(msgRec.indexOf("reason")).toString() + "~time:";
        userMsg += query.value(msgRec.indexOf("time")).toString() + "~end()";
    }

    result = adminMsg + "~user:" + userMsg;

}

void QSimpleServer::insertMsg(const QString &id, const QString &txt)
{
    //setMsgs:INSERT INTO pays (mid, reason, time, type, category) VALUES (%1, %2, %3, %4, %5)

    // INSERT INTO pays (mid, reason, time, type, category) VALUES (27720, "Test-message line", 1536271400, 30, 491)

    QString que = map.value("setMsgs:")
            .arg(id)    // mid
            .arg("'" + txt + "'")   // reason
            .arg("'Через мобильное приложение.'")
            .arg(now.currentDateTime().toSecsSinceEpoch())   // time
            .arg(30)    // type
            .arg(491);  // category

    query.exec(que);
    //qDebug() << "Last SQL error: " << query.lastError();

}

void QSimpleServer::queryToSql(const QString& id, const QString &key, QString &answer)
{
    QString quest = map.value(key);

    //QSqlQuery query;

    if(id[0].isDigit())
        query.exec(quest + " id=" + id);
    else
        query.exec(quest + " name='" + id + "'");

    // QSqlRecord rec = query.record();

    short q(0);

    for(auto &c:quest)
    {
        if(c == ',')
            ++q;
    }
    ++q;

    short i(0);

    while (query.next()) {

        while(i != q)
        {
            answer += query.value(i).toString();
            answer += " ";
            ++i;
        }
    }
    i = 0;
    q = 0;
    //qDebug() << "answer: " + answer;

}

void QSimpleServer::askSql(const QString &ident, const QString &key, QString &answer)
{
    //qDebug() << "OK, this is a new code.";

    QString quest = map.value(key);

    query.exec(quest + ident);

    int row = query.size();
    int column = query.record().count();

    // qDebug() << "Строк: " << row << ", столбцов: " << column;



    QSqlQueryModel model;

    model.setQuery(quest + ident);


    if(model.lastError().isValid())
        qDebug() << model.lastError();


    QVector<QString> times_vct, cashes_vct, comments_vct;

    int i(0);
    int j(0);

    QString sqlRec;

    while (j != column)
    {
        while(i != row)
        {
            sqlRec += model.record(i).value(j).toString() + ' ';

            if(j == 0)
            {
                //  qDebug() << i << ": " << sqlRec;
                times_vct.push_back(sqlRec);
                sqlRec.clear();
            }

            if(j == 1)
            {
                // qDebug() << i << ": " << sqlRec;
                cashes_vct.push_back(sqlRec);
                sqlRec.clear();
            }

            if(j == 2)
            {
                //sqlRec += 'R';
                //  qDebug() << i << ": " << sqlRec;
                comments_vct.push_back(sqlRec);
                sqlRec.clear();
            }
            ++i;
        }

        i = 0;
        ++j;
    }


    for(auto &sstr:times_vct)
    {
        //qDebug() << sstr;
        answer += sstr;
    }

    answer += "t";

    for(auto &sstr:cashes_vct)
    {
        //qDebug() << str;
        answer += sstr;
    }

    answer += "$";

    //qDebug() << "Now comments_vct parsing: ";
    for(auto &sstr:comments_vct)
    {
        //qDebug() << sstr;
        answer += sstr + '~';
    }

    answer += "@";

    //qDebug() << "Next information will be sent: ";
    //qDebug() << answer;

}

bool QSimpleServer::readConfig(QStringList &line)
{
    QFile in("config");
    if (!in.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << in.errorString() + '\n';
        qDebug() << "Unable to read the configuration file. \nFirstly, check the location.";
        return false;
    }else{
        qDebug() << "Open configuration file.... ok";

        while (!in.atEnd()) {
            QString temp = in.readLine();
            QString str;
            for(auto &c:temp)
            {
                if(c == '\n' || c == '\t')
                    break;
                str += c;
            }
            line.push_back(str);
        }
        in.close();
    }
    return true;
}

void QSimpleServer::updateSql(const QString &id, const QString &key, const QString arg)
{
    // id - кто клиент
    // que - текст запроса
    // arg - аргумент (например: UPDATE users SET next_paket=7(arg) WHERE id=12855(id)) (que)
    // UPDATE users SET auth WHERE

    QString t_quest = map.value(key);

    QString quest;

    QString t_param, param;

    for(auto &c:t_quest)      // quest    'UPDATE users SET '
    {
        quest += c;
        if(quest.right(3) == "SET"){
            t_param = t_quest.mid(quest.length() + 1);
            break;
        }

    }

    // Now    t_param = "auth WHERE"
    //        quest = "UPDATE users SET"

    for(auto &c:t_param)      // param    'next_paket'
    {
        if(c == ' ')
            break;
        param += c;
    }

    quest += ' ' + param + "=" + arg + ' ';

    // UPDATE users SET auth=arg WHERE id=12345

    //quest += ' ' + param + "='" + arg + "' ";


    if(id[0].isDigit())
    {
        query.exec(quest + "WHERE id=" + id);
    }
    else
    {
        query.exec(quest + "WHERE name='" + id + "'");
    }


}

bool QSimpleServer::chekAuth(const QString &id, const QString &pass)
{
    if (id[0].isDigit())
        query.exec("SELECT passwd, AES_DECRYPT(passwd, 'hardpass3')"
                   " AS PASSWORD FROM users WHERE id=" + id);
    else query.exec("SELECT passwd, AES_DECRYPT(passwd, 'hardpass3')"
                    " AS PASSWORD FROM users WHERE name='" + id + "'");

    if (db.isOpen())
    {
        while (query.next())
            passwd = query.value(1).toString();   // passwd - строка с верным паролем

    }

    QCryptographicHash passHash(QCryptographicHash::Keccak_256);
    passHash.addData(passwd.toUtf8());

    if (pass == QString::fromStdString(passHash.result().toHex().toStdString()))
    {
        qDebug() << "Right authorization.";
        return true;
    }
    else
        return false;
}

void QSimpleServer::onDisconnected()
{
    QSslSocket* socket = qobject_cast<QSslSocket*> (sender());
    socket->close();
    socket->deleteLater();
    qDebug() << "On disconnect!";
}













void QSimpleServer::scanSwich(const QString& s)
{
    manager->get(QNetworkRequest(QUrl("http://stat.vbg/cgi-bin/ramon/mac.pl?a=cab&ip=" + s)));
}



void QSimpleServer::replyFinished(QNetworkReply* reply)
{

    QByteArray data = reply->readAll();

    QString whole_str(QString::fromStdString(data.toStdString()));

    qDebug() << whole_str << '\n';


}
















