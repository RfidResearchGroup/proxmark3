//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// GUI (QT)
//-----------------------------------------------------------------------------

#ifndef PROXGUI_QT
#define PROXGUI_QT

#include <stdint.h>
#include <string.h>

#include <QApplication>
#include <QPushButton>
#include <QObject>
#include <QWidget>
#include <QPainter>
#include <QtGui>

#include "ui/ui_overlays.h"

class ProxWidget;

/**
 * @brief The actual plot, black area were we paint the graph
 */
class Plot: public QWidget {
  private:
    QWidget *master;
    int GraphStart;
    double GraphPixelsPerPoint;
    int CursorAPos;
    int CursorBPos;
    void PlotGraph(int *buffer, int len, QRect r, QRect r2, QPainter *painter, int graphNum);
    void PlotDemod(uint8_t *buffer, size_t len, QRect r, QRect r2, QPainter *painter, int graphNum, int plotOffset);
    void plotGridLines(QPainter *painter, QRect r);
    int xCoordOf(int i, QRect r);
    int yCoordOf(int v, QRect r, int maxVal);
    int valueOf_yCoord(int y, QRect r, int maxVal);
    void setMaxAndStart(int *buffer, int len, QRect plotRect);
    QColor getColor(int graphNum);

  public:
    Plot(QWidget *parent = 0);

  protected:
    void paintEvent(QPaintEvent *event);
    void closeEvent(QCloseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);
    void mousePressEvent(QMouseEvent *event) { mouseMoveEvent(event); }
    void keyPressEvent(QKeyEvent *event);
};
class ProxGuiQT;

/**
 * The window with plot and controls
 */
class ProxWidget : public QWidget {
    Q_OBJECT; //needed for slot/signal classes

  private:
    ProxGuiQT *master;
    Plot *plot;
    Ui::Form *opsController;
    QWidget *controlWidget;

  public:
    ProxWidget(QWidget *parent = 0, ProxGuiQT *master = NULL);
    ~ProxWidget(void);
    //OpsShow(void);

  protected:
    //  void paintEvent(QPaintEvent *event);
    void closeEvent(QCloseEvent *event);
    void showEvent(QShowEvent *event);
    void hideEvent(QHideEvent *event);
    //  void mouseMoveEvent(QMouseEvent *event);
    //  void mousePressEvent(QMouseEvent *event) { mouseMoveEvent(event); }
    //  void keyPressEvent(QKeyEvent *event);
  public slots:
    void applyOperation();
    void stickOperation();
    void vchange_autocorr(int v);
    void vchange_askedge(int v);
    void vchange_dthr_up(int v);
    void vchange_dthr_down(int v);
};

class WorkerThread : public QThread {
    Q_OBJECT;
  public:
    WorkerThread(char *, char *, bool);
    ~WorkerThread();
    void run();
  private:
    char *script_cmds_file = NULL;
    char *script_cmd = NULL;
    bool usb_present;
};

class ProxGuiQT : public QObject {
    Q_OBJECT;

  private:
    QApplication *plotapp;
    ProxWidget *plotwidget;
    int argc;
    char **argv;
    //void (*main_func)(void);
    WorkerThread *proxmarkThread;

  public:
    ProxGuiQT(int argc, char **argv, WorkerThread *wthread);
    ~ProxGuiQT(void);
    void ShowGraphWindow(void);
    void RepaintGraphWindow(void);
    void HideGraphWindow(void);
    void MainLoop(void);
    void Exit(void);

  private slots:
    void _ShowGraphWindow(void);
    void _RepaintGraphWindow(void);
    void _HideGraphWindow(void);
    void _Exit(void);
    void _StartProxmarkThread(void);

  signals:
    void ShowGraphWindowSignal(void);
    void RepaintGraphWindowSignal(void);
    void HideGraphWindowSignal(void);
    void ExitSignal(void);
};

#endif // PROXGUI_QT
