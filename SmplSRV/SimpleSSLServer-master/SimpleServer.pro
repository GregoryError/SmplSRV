QT += core
QT -= gui
QT += network
QT += sql

TARGET = SimpleServer
CONFIG += console
CONFIG -= app_bundle
CONFIG += c++11

TEMPLATE = app

SOURCES += main.cpp \
    qsimpleserver.cpp

HEADERS += \
    qsimpleserver.h

RESOURCES +=

