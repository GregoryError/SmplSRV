#include <QCoreApplication>
#include "qsimpleserver.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);


    a.addLibraryPath(QCoreApplication::applicationDirPath() + QLatin1String("/plugins"));
    a.addLibraryPath(QCoreApplication::applicationDirPath() + QLatin1String("/plugins/sqldrivers"));
    a.addLibraryPath(QCoreApplication::applicationDirPath() + QLatin1String("/lib"));
    a.addLibraryPath(QCoreApplication::applicationDirPath());
    a.setApplicationName("Успех");

    //  qDebug() << "libraryPaths: ";
    //  QStringList lst =  a.libraryPaths();
    //  foreach (QString str, lst) {
    //     qDebug() << QTime::currentTime().toString() + ": " + str;
    //  }

    QSimpleServer server;

    // if(server.listen(QHostAddress::Any, 1234))
    //      qDebug() << "Listening...";
    //      else qDebug() << "Error while starting: " + server.errorString();
    //


    Q_UNUSED(server);

    return a.exec();
}
