//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
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
#include "ui/ui_image.h"

class ProxWidget;

/**
 * @brief The actual plot, black area were we paint the graph
 */
class Plot: public QWidget {
  private:
    QWidget *master;
    double g_GraphPixelsPerPoint; // How many visual pixels are between each sample point (x axis)
    uint32_t CursorAPos;
    uint32_t CursorBPos;
    void PlotGraph(int *buffer, size_t len, QRect plotRect, QRect annotationRect, QPainter *painter, int graphNum);
    void PlotDemod(uint8_t *buffer, size_t len, QRect plotRect, QRect annotationRect, QPainter *painter, int graphNum, uint32_t plotOffset);
    void plotGridLines(QPainter *painter, QRect r);
    int xCoordOf(int i, QRect r);
    int yCoordOf(int v, QRect r, int maxVal);
    int valueOf_yCoord(int y, QRect r, int maxVal);
    void setMaxAndStart(int *buffer, size_t len, QRect plotRect);
    QColor getColor(int graphNum);

  public:
    Plot(QWidget *parent = 0);

  protected:
    void paintEvent(QPaintEvent *event);
    void closeEvent(QCloseEvent *event);
    void Zoom(double factor, uint32_t refX);
    void Move(int offset);
    void Trim(void);
    void wheelEvent(QWheelEvent *event);
    void mouseMoveEvent(QMouseEvent *event);
    void mousePressEvent(QMouseEvent *event) { mouseMoveEvent(event); }
    void keyPressEvent(QKeyEvent *event);
};
class ProxGuiQT;

// Added class for SliderWidget to allow move/resize event override
class SliderWidget : public QWidget {
  protected:
    void resizeEvent(QResizeEvent *event);
    void moveEvent(QMoveEvent *event);
  public:
    SliderWidget();
};

// Added class for SliderWidget to allow move/resize event override
class PictureWidget : public QWidget {
  protected:
    void closeEvent(QCloseEvent *event);
  public:
    PictureWidget();
};

/**
 * The window with plot and controls
 */

class ProxWidget : public QWidget {
    Q_OBJECT; //needed for slot/signal classes

  private:
    ProxGuiQT *master;
    Plot *plot;
    Ui::Form *opsController;
    SliderWidget *controlWidget;

  public:
    ProxWidget(QWidget *parent = 0, ProxGuiQT *master = NULL);
    ~ProxWidget(void);
    //OpsShow(void);

  protected:
    //  void paintEvent(QPaintEvent *event);
    void closeEvent(QCloseEvent *event);
    void showEvent(QShowEvent *event);
    void hideEvent(QHideEvent *event);
    void moveEvent(QMoveEvent *event);
    void resizeEvent(QResizeEvent *event);
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
    char *script_cmds_file;
    char *script_cmd;
    bool stayInCommandLoop;
};

class ProxGuiQT : public QObject {
    Q_OBJECT;

  private:
    QApplication *plotapp;
    ProxWidget *plotwidget;
    Ui::PictureForm *pictureController;
    PictureWidget *pictureWidget;

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

    // hook up picture viewer
    void ShowPictureWindow(const QImage &img);
    void ShowBase64PictureWindow(char *b64);
    void HidePictureWindow(void);
    void RepaintPictureWindow(void);

    void MainLoop(void);
    void Exit(void);

  private slots:
    void _ShowGraphWindow(void);
    void _RepaintGraphWindow(void);
    void _HideGraphWindow(void);

    // hook up picture viewer
    void _ShowPictureWindow(const QImage &img);
    void _ShowBase64PictureWindow(char *b64);
    void _HidePictureWindow(void);
    void _RepaintPictureWindow(void);

    void _Exit(void);
    void _StartProxmarkThread(void);

  signals:
    void ShowGraphWindowSignal(void);
    void RepaintGraphWindowSignal(void);
    void HideGraphWindowSignal(void);
    void ExitSignal(void);

    // hook up picture viewer signals
    void ShowPictureWindowSignal(const QImage &img);
    void ShowBase64PictureWindowSignal(char *b64);
    void HidePictureWindowSignal(void);
    void RepaintPictureWindowSignal(void);
};

#endif // PROXGUI_QT
