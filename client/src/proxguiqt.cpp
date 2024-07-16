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
#define __STDC_FORMAT_MACROS
#include "proxguiqt.h"
#include <inttypes.h>
#include <stdbool.h>
#include <iostream>
//#include <QtCore>
#include <QPainterPath>
#include <QBrush>
#include <QPen>
#include <QTimer>
#include <QCloseEvent>
#include <QMouseEvent>
#include <QKeyEvent>
#include <math.h>
#include <limits.h>
#include <stdio.h>
#include <QSlider>
#include <QHBoxLayout>
#include <string.h>
#include <QtGui>
#include "proxgui.h"
#include "ui.h"
#include "comms.h"
#include "graph.h"
#include "cmddata.h"
#include "util_darwin.h"
//#include "fileutils.h"

extern "C" int preferences_save(void);

static int gs_absVMax = 0;
static uint32_t startMax; // Maximum offset in the graph (right side of graph)
static uint32_t startMaxOld;
static uint32_t PageWidth; // How many samples are currently visible on this 'page' / graph
static int unlockStart = 0;

void ProxGuiQT::ShowGraphWindow(void) {
    emit ShowGraphWindowSignal();
}

void ProxGuiQT::RepaintGraphWindow(void) {
    emit RepaintGraphWindowSignal();
}

void ProxGuiQT::HideGraphWindow(void) {
    emit HideGraphWindowSignal();
}

// emit picture viewer signals
void ProxGuiQT::ShowPictureWindow(const QImage &img) {
    emit ShowPictureWindowSignal(img);
}

void ProxGuiQT::ShowBase64PictureWindow(char *b64) {
    emit ShowBase64PictureWindowSignal(b64);
}

void ProxGuiQT::RepaintPictureWindow(void) {
    emit RepaintPictureWindowSignal();
}

void ProxGuiQT::HidePictureWindow(void) {
    emit HidePictureWindowSignal();
}

void ProxGuiQT::Exit(void) {
    emit ExitSignal();
}

void ProxGuiQT::_ShowGraphWindow(void) {
    if (!plotapp)
        return;

    if (!plotwidget) {

#if defined(__MACH__) && defined(__APPLE__)
        makeFocusable();
#endif

        plotwidget = new ProxWidget();
    }
    plotwidget->show();

}

void ProxGuiQT::_RepaintGraphWindow(void) {
    if (!plotapp || !plotwidget)
        return;

    plotwidget->update();
}

void ProxGuiQT::_HideGraphWindow(void) {
    if (!plotapp || !plotwidget)
        return;

    plotwidget->hide();
}

// picture viewer
void ProxGuiQT::_ShowPictureWindow(const QImage &img) {

    if (!plotapp)
        return;

    if (img.isNull())
        return;

    if (!pictureWidget) {

#if defined(__MACH__) && defined(__APPLE__)
        makeFocusable();
#endif

        pictureWidget = new PictureWidget();
    }

    QPixmap pm = QPixmap::fromImage(img);

    //QPixmap newPixmap = pm.scaled(QSize(50,50),  Qt::KeepAspectRatio);
    //pm = pm.scaled(pictureController->lbl_pm->size(),  Qt::KeepAspectRatio);

    pictureController->lbl_pm->setPixmap(pm);
    pictureController->lbl_pm->setScaledContents(false);
    pictureController->lbl_pm->setAlignment(Qt::AlignCenter);

    QString s = QString("w: %1  h: %2")
                .arg(pm.size().width())
                .arg(pm.size().height()
                    );
    pictureController->lbl_sz->setText(s);
    pictureWidget->show();

}

void ProxGuiQT::_ShowBase64PictureWindow(char *b64) {

    if (!plotapp)
        return;

    if (b64 == NULL)
        return;

    size_t slen = strlen(b64);
    if (slen == 0)
        return;

    char *myb64data = (char *)calloc(slen + 1, sizeof(uint8_t));
    if (myb64data == NULL)
        return;

    memcpy(myb64data, b64, slen);

    if (!pictureWidget) {

#if defined(__MACH__) && defined(__APPLE__)
        makeFocusable();
#endif

        pictureWidget = new PictureWidget();
    }

    QPixmap pm;
    if (pm.loadFromData(QByteArray::fromBase64(myb64data), "PNG") == false) {
        qWarning("Failed to read base64 data: %s", myb64data);
    }
    free(myb64data);
    //free(b64);

    pictureController->lbl_pm->setPixmap(pm);
    pictureController->lbl_pm->setScaledContents(false);
    pictureController->lbl_pm->setAlignment(Qt::AlignCenter);

    QString s = QString("w: %1  h: %2")
                .arg(pm.size().width())
                .arg(pm.size().height()
                    );
    pictureController->lbl_sz->setText(s);
    pictureWidget->show();

}

void ProxGuiQT::_RepaintPictureWindow(void) {
    if (!plotapp || !pictureWidget)
        return;

    pictureWidget->update();

}

void ProxGuiQT::_HidePictureWindow(void) {
    if (!plotapp || !pictureWidget)
        return;

    pictureWidget->hide();
}

void ProxGuiQT::_Exit(void) {
    delete this;
}

void ProxGuiQT::_StartProxmarkThread(void) {
    if (!proxmarkThread)
        return;

    // if thread finished delete self and delete application
    QObject::connect(proxmarkThread, SIGNAL(finished()), proxmarkThread, SLOT(deleteLater()));
    QObject::connect(proxmarkThread, SIGNAL(finished()), this, SLOT(_Exit()));
    // start proxmark thread
    proxmarkThread->start();
}

void ProxGuiQT::MainLoop() {
    plotapp = new QApplication(argc, argv);

    // Setup the picture widget
    pictureWidget = new PictureWidget();
    pictureController = new Ui::PictureForm();
    pictureController->setupUi(pictureWidget);
//    pictureWidget->setAttribute(Qt::WA_DeleteOnClose,true);

    // Set picture widget position if no settings.
    if (g_session.preferences_loaded == false) {
        // Move controller widget below plot
        //pictureController->move(x(), y() + frameSize().height());
        //pictureController->resize(size().width(), 200);
    }

    connect(this, SIGNAL(ShowGraphWindowSignal()), this, SLOT(_ShowGraphWindow()));
    connect(this, SIGNAL(RepaintGraphWindowSignal()), this, SLOT(_RepaintGraphWindow()));
    connect(this, SIGNAL(HideGraphWindowSignal()), this, SLOT(_HideGraphWindow()));

    connect(this, SIGNAL(ExitSignal()), this, SLOT(_Exit()));

    // hook up picture viewer signals
    connect(this, SIGNAL(ShowPictureWindowSignal(const QImage &)), this, SLOT(_ShowPictureWindow(const QImage &)));
    connect(this, SIGNAL(ShowBase64PictureWindowSignal(char *)), this, SLOT(_ShowBase64PictureWindow(char *)));
    connect(this, SIGNAL(RepaintPictureWindowSignal()), this, SLOT(_RepaintPictureWindow()));
    connect(this, SIGNAL(HidePictureWindowSignal()), this, SLOT(_HidePictureWindow()));

    //start proxmark thread after starting event loop
    QTimer::singleShot(200, this, SLOT(_StartProxmarkThread()));

#if defined(__MACH__) && defined(__APPLE__)
    //Prevent the terminal from loosing focus during launch by making the client unfocusable
    makeUnfocusable();
#endif

    plotapp->exec();
}

ProxGuiQT::ProxGuiQT(int argc, char **argv, WorkerThread *wthread) :
    plotapp(NULL), plotwidget(NULL), pictureController(NULL), pictureWidget(NULL), argc(argc), argv(argv), proxmarkThread(wthread) {

}

ProxGuiQT::~ProxGuiQT(void) {

    if (pictureController) {
        delete pictureController;
        pictureController = NULL;
    }

    if (pictureWidget) {
        pictureWidget->close();
        delete pictureWidget;
        pictureWidget = NULL;
    }

    if (plotapp) {
        plotapp->quit();
        plotapp = NULL;
    }
}

// -------------------------------------------------
// Slider Widget form based on a class to enable
// Event override functions
// -------------------------------------------------
PictureWidget::PictureWidget() {
    // Set the initial position and size from settings
//    if (g_session.preferences_loaded)
//        setGeometry(g_session.pw.x, g_session.pw.y, g_session.pw.w, g_session.pw.h);
//    else
    resize(400, 400);
}

void PictureWidget::closeEvent(QCloseEvent *event) {
    this->hide();
    event->ignore();
}


// -------------------------------------------------
// Slider Widget form based on a class to enable
// Event override functions
// -------------------------------------------------

SliderWidget::SliderWidget() {
    // Set the initial position and size from settings
    if (g_session.preferences_loaded)
        setGeometry(g_session.overlay.x, g_session.overlay.y, g_session.overlay.w, g_session.overlay.h);
    else
        resize(800, 400);
}

void SliderWidget::resizeEvent(QResizeEvent *event) {
    g_session.overlay.h = event->size().height();
    g_session.overlay.w = event->size().width();
    g_session.window_changed = true;

}

void SliderWidget::moveEvent(QMoveEvent *event) {
    g_session.overlay.x = event->pos().x();
    g_session.overlay.y = event->pos().y();
    g_session.window_changed = true;
}

//--------------------
void ProxWidget::applyOperation() {
    //printf("ApplyOperation()");
    //g_saveState_gb = save_bufferS32(g_GraphBuffer, g_GraphTraceLen);
    memcpy(g_GraphBuffer, g_OverlayBuffer, sizeof(int) * g_GraphTraceLen);
    RepaintGraphWindow();
}
void ProxWidget::stickOperation() {
    //restore_bufferS32(g_saveState_gb, g_GraphBuffer);
    //printf("stickOperation()");
}
void ProxWidget::vchange_autocorr(int v) {
    int ans = AutoCorrelate(g_GraphBuffer, g_OverlayBuffer, g_GraphTraceLen, v, true, false);
    if (g_debugMode) printf("vchange_autocorr(w:%d): %d\n", v, ans);
    g_useOverlays = true;
    RepaintGraphWindow();
}
void ProxWidget::vchange_askedge(int v) {
    //extern int AskEdgeDetect(const int *in, int *out, int len, int threshold);
    int ans = AskEdgeDetect(g_GraphBuffer, g_OverlayBuffer, g_GraphTraceLen, v);
    if (g_debugMode) printf("vchange_askedge(w:%d)%d\n", v, ans);
    g_useOverlays = true;
    RepaintGraphWindow();
}
void ProxWidget::vchange_dthr_up(int v) {
    int down = opsController->horizontalSlider_dirthr_down->value();
    directionalThreshold(g_GraphBuffer, g_OverlayBuffer, g_GraphTraceLen, v, down);
    //printf("vchange_dthr_up(%d)", v);
    g_useOverlays = true;
    RepaintGraphWindow();
}
void ProxWidget::vchange_dthr_down(int v) {
    //printf("vchange_dthr_down(%d)", v);
    int up = opsController->horizontalSlider_dirthr_up->value();
    directionalThreshold(g_GraphBuffer, g_OverlayBuffer, g_GraphTraceLen, v, up);
    g_useOverlays = true;
    RepaintGraphWindow();
}

void ProxWidget::updateNavSlider() {
    navSlider->blockSignals(true);
    navSlider->setValue(g_GraphStart);
    navSlider->setMaximum(startMax);
    // for startMaxOld < g_GraphStart or startMax < g_GraphStart_old
    navSlider->setValue(g_GraphStart);
    navSlider->setMaximum(startMax);
    // for click
    navSlider->setPageStep(startMax / 10);
    navSlider->blockSignals(false);
}


ProxWidget::ProxWidget(QWidget *parent, ProxGuiQT *master) : QWidget(parent) {
    this->master = master;
    // Set the initial position and size from settings
    if (g_session.preferences_loaded)
        setGeometry(g_session.plot.x, g_session.plot.y, g_session.plot.w, g_session.plot.h);
    else
        resize(800, 400);

    // Setup the controller widget
    controlWidget = new SliderWidget();
    opsController = new Ui::Form();
    opsController->setupUi(controlWidget);
    //Due to quirks in QT Designer, we need to fiddle a bit
    opsController->horizontalSlider_dirthr_down->setMinimum(-128);
    opsController->horizontalSlider_dirthr_down->setMaximum(0);
    opsController->horizontalSlider_dirthr_down->setValue(-20);
    opsController->horizontalSlider_dirthr_up->setMinimum(-40);
    opsController->horizontalSlider_dirthr_up->setMaximum(128);
    opsController->horizontalSlider_dirthr_up->setValue(20);
    opsController->horizontalSlider_askedge->setValue(25);
    opsController->horizontalSlider_window->setValue(4000);

    QObject::connect(opsController->pushButton_apply, SIGNAL(clicked()), this, SLOT(applyOperation()));
    QObject::connect(opsController->pushButton_sticky, SIGNAL(clicked()), this, SLOT(stickOperation()));
    QObject::connect(opsController->horizontalSlider_window, SIGNAL(valueChanged(int)), this, SLOT(vchange_autocorr(int)));
    QObject::connect(opsController->horizontalSlider_dirthr_up, SIGNAL(valueChanged(int)), this, SLOT(vchange_dthr_up(int)));
    QObject::connect(opsController->horizontalSlider_dirthr_down, SIGNAL(valueChanged(int)), this, SLOT(vchange_dthr_down(int)));
    QObject::connect(opsController->horizontalSlider_askedge, SIGNAL(valueChanged(int)), this, SLOT(vchange_askedge(int)));

    controlWidget->setGeometry(g_session.overlay.x, g_session.overlay.y, g_session.overlay.w, g_session.overlay.h);

    // Set up the plot widget, which does the actual plotting
    plot = new Plot(this);
    navSlider = new QSlider(this);
    QVBoxLayout *layout = new QVBoxLayout;
    layout->addWidget(plot, 1);
    layout->addWidget(navSlider);
    setLayout(layout);

    navSlider->setOrientation(Qt::Horizontal);
    plot->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    navSlider->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    QObject::connect(navSlider, SIGNAL(valueChanged(int)), plot, SLOT(MoveTo(int)));
    QObject::connect(plot, SIGNAL(startMaxChanged(uint32_t)), this, SLOT(updateNavSlider(void)));
    QObject::connect(plot, SIGNAL(graphStartChanged(uint32_t)), this, SLOT(updateNavSlider(void)));

    // plot window title
    QString pt = QString("[*]Plot [ %1 ]").arg(g_conn.serial_port_name);
    setWindowTitle(pt);

    // shows plot window on the screen.
    show();

    // Set Slider/Overlay position if no settings.
    if (g_session.preferences_loaded == false) {
        // Move controller widget below plot
        controlWidget->move(x(), y() + frameSize().height());
        controlWidget->resize(size().width(), 200);
    }

    // Overlays / slider window title
    QString ct = QString("[*]Slider [ %1 ]").arg(g_conn.serial_port_name);
    controlWidget->setWindowTitle(ct);

    // The hide/show event functions should take care of this.
    //  controlWidget->show();

    // now that is up, reset pos/size change flags
    g_session.window_changed = false;

}

// not 100% sure what i need in this block
// feel free to fix - marshmellow...
ProxWidget::~ProxWidget(void) {
    if (controlWidget) {
        controlWidget->close();
        delete controlWidget;
        controlWidget = NULL;
    }

    if (opsController) {
        delete opsController;
        opsController = NULL;
    }

    if (plot) {
        plot->close();
        delete plot;
        plot = NULL;
    }
}

void ProxWidget::closeEvent(QCloseEvent *event) {
    event->ignore();
    this->hide();
    g_useOverlays = false;
}
void ProxWidget::hideEvent(QHideEvent *event) {
    controlWidget->hide();
    plot->hide();
}
void ProxWidget::showEvent(QShowEvent *event) {
    if (g_session.overlay_sliders)
        controlWidget->show();
    else
        controlWidget->hide();

    plot->show();
}
void ProxWidget::moveEvent(QMoveEvent *event) {
    g_session.plot.x = event->pos().x();
    g_session.plot.y = event->pos().y();
    g_session.window_changed = true;
}
void ProxWidget::resizeEvent(QResizeEvent *event) {
    g_session.plot.h = event->size().height();
    g_session.plot.w = event->size().width();
    g_session.window_changed = true;
}

//----------- Plotting

int Plot::xCoordOf(int i, QRect r) {
    return r.left() + (int)((i - g_GraphStart) * g_GraphPixelsPerPoint);
}

int Plot::yCoordOf(int v, QRect r, int maxVal) {
    int z = (r.bottom() - r.top()) / 2;
    if (maxVal == 0) {
        ++maxVal;
    }
    return -(z * v) / maxVal + z;
}

int Plot::valueOf_yCoord(int y, QRect r, int maxVal) {
    int z = (r.bottom() - r.top()) / 2;
    return (y - z) * maxVal / z;
}

static const QColor BLACK     = QColor(0, 0, 0);
static const QColor GRAY60    = QColor(60, 60, 60);
static const QColor GRAY100   = QColor(100, 100, 100);
static const QColor GRAY240   = QColor(240, 240, 240);
static const QColor WHITE     = QColor(255, 255, 255);
static const QColor GREEN     = QColor(100, 255, 100);
static const QColor RED       = QColor(255, 100, 100);
static const QColor BLUE      = QColor(100, 100, 255);
static const QColor YELLOW    = QColor(255, 255, 0);
static const QColor CITRON    = QColor(215, 197, 46);
static const QColor PINK      = QColor(255, 0, 255);
static const QColor ORANGE    = QColor(255, 153, 0);
static const QColor LIGHTBLUE = QColor(100, 209, 246);

QColor Plot::getColor(int graphNum) {
    switch (graphNum) {
        case 0:
            return GREEN;
        case 1:
            return RED;
        case 2:
            return BLUE;
        default:
            return GRAY240;
    }
}

void Plot::setMaxAndStart(int *buffer, size_t len, QRect plotRect) {
    if (len == 0) {
        return;
    }

    startMax = 0;

    if (plotRect.right() >= plotRect.left() + 40) {
        uint32_t t = (plotRect.right() - plotRect.left() - 40) / g_GraphPixelsPerPoint;
        if (len >= t) {
            startMax = len - t;
        }
    }

    if (g_GraphStart > startMax) {
        g_GraphStart = startMax;
    }

    if (g_GraphStart > len) {
        return;
    }

    int vMin = INT_MAX, vMax = INT_MIN;
    uint32_t sample_index = g_GraphStart ;
    for (; sample_index < len && xCoordOf(sample_index, plotRect) < plotRect.right() ; sample_index++) {

        int v = buffer[sample_index];
        if (v < vMin) vMin = v;
        if (v > vMax) vMax = v;
    }

    gs_absVMax = 0;
    if (fabs((double) vMin) > gs_absVMax) {
        gs_absVMax = (int)fabs((double) vMin);
    }

    if (fabs((double) vMax) > gs_absVMax) {
        gs_absVMax = (int)fabs((double) vMax);
    }

    gs_absVMax = (int)(gs_absVMax * 1.25 + 1);
}

void Plot::appendMax(int *buffer, size_t len, QRect plotRect) {
    if (len == 0) {
        return;
    }

    int vMin = INT_MAX, vMax = INT_MIN;
    uint32_t sample_index = g_GraphStart ;

    for (; sample_index < len && xCoordOf(sample_index, plotRect) < plotRect.right() ; sample_index++) {

        int v = buffer[sample_index];
        if (v < vMin) vMin = v;
        if (v > vMax) vMax = v;
    }

    if (fabs((double) vMin) > gs_absVMax) {
        gs_absVMax = (int)fabs((double) vMin);
    }

    if (fabs((double) vMax) > gs_absVMax) {
        gs_absVMax = (int)fabs((double) vMax);
    }

    gs_absVMax = (int)(gs_absVMax * 1.25 + 1);
}

void Plot::PlotDemod(uint8_t *buffer, size_t len, QRect plotRect, QRect annotationRect, QPainter *painter, int graphNum, uint32_t plotOffset) {

    if (len == 0 || g_PlotGridX <= 0) {
        return;
    }

    QPainterPath penPath;

    int grid_delta_x = g_PlotGridX;
    int first_delta_x = grid_delta_x; //(plotOffset > 0) ? g_PlotGridX : (g_PlotGridX +);
    if (g_GraphStart > plotOffset) first_delta_x -= (g_GraphStart - plotOffset);
    int DemodStart = g_GraphStart;
    if (plotOffset > g_GraphStart) DemodStart = plotOffset;

    int BitStart = 0;
    // round down
    if (DemodStart - plotOffset > 0) BitStart = (int)(((DemodStart - plotOffset) + (g_PlotGridX - 1)) / g_PlotGridX) - 1;
    first_delta_x += BitStart * g_PlotGridX;
    if (BitStart > (int)len) return;
    int delta_x = 0;
//    int v = 0;
    //printf("first_delta_x %i, grid_delta_x %i, DemodStart %i, BitStart %i\n",first_delta_x,grid_delta_x,DemodStart, BitStart);

    painter->setPen(getColor(graphNum));
    char str[5];
    int absVMax = (int)(100 * 1.05 + 1);
    delta_x = 0;
    int clk = first_delta_x;
    for (int i = BitStart; i < (int)len && xCoordOf(delta_x + DemodStart, plotRect) < plotRect.right(); i++) {
        for (int j = 0; j < (clk) && i < (int)len && xCoordOf(DemodStart + delta_x + j, plotRect) < plotRect.right() ; j++) {
            int x = xCoordOf(DemodStart + delta_x + j, plotRect);
            int v = buffer[i] * 200 - 100;

            int y = yCoordOf(v, plotRect, absVMax);
            if ((i == BitStart) && (j == 0)) { // First point
                penPath.moveTo(x, y);
            } else {
                penPath.lineTo(x, y);
            }
            if (g_GraphPixelsPerPoint > 10) {
                QRect f(QPoint(x - 3, y - 3), QPoint(x + 3, y + 3));
                painter->fillRect(f, getColor(graphNum));
            }
            if (j == (int)clk / 2) {
                //print label
                snprintf(str, sizeof(str), "%u", buffer[i]);
                painter->drawText(x - 8, y + ((buffer[i] > 0) ? 18 : -6), str);
            }
        }
        delta_x += clk;
        clk = grid_delta_x;
    }

    painter->drawPath(penPath);
}

void Plot::PlotGraph(int *buffer, size_t len, QRect plotRect, QRect annotationRect, QPainter *painter, int graphNum) {

    if (len == 0) {
        return;
    }

    QPainterPath penPath;
    int64_t vMean = 0;
    uint32_t i = 0;
    int vMin = INT_MAX, vMax = INT_MIN, v = 0;
    int x = xCoordOf(g_GraphStart, plotRect);
    int y = yCoordOf(buffer[g_GraphStart], plotRect, gs_absVMax);
    penPath.moveTo(x, y);
    for (i = g_GraphStart; i < len && xCoordOf(i, plotRect) < plotRect.right(); i++) {

        x = xCoordOf(i, plotRect);
        v = buffer[i];
        y = yCoordOf(v, plotRect, gs_absVMax);

        penPath.lineTo(x, y);

        if (g_GraphPixelsPerPoint > 10) {
            QRect f(QPoint(x - 3, y - 3), QPoint(x + 3, y + 3));
            painter->fillRect(f, GREEN);
        }
        // catch stats
        if (v < vMin) vMin = v;
        if (v > vMax) vMax = v;
        vMean += v;
    }

    g_GraphStop = i;
    vMean /= (g_GraphStop - g_GraphStart);

    painter->setPen(getColor(graphNum));

    // Draw y-axis
    int xo = 5 + (graphNum * 40);
    painter->drawLine(xo, plotRect.top(), xo, plotRect.bottom());

    int vMarkers = (gs_absVMax - (gs_absVMax % 10)) / 5;
    int minYDist = 40; // Minimum pixel-distance between markers

    char yLbl[20];

    int n = 0;
    int lasty0 = 65535;

    for (v = vMarkers; yCoordOf(v, plotRect, gs_absVMax) > plotRect.top() && n < 20; v += vMarkers, n++) {
        int y0 = yCoordOf(v, plotRect, gs_absVMax);
        int y1 = yCoordOf(-v, plotRect, gs_absVMax);

        if (lasty0 - y0 < minYDist) {
            continue;
        }

        painter->drawLine(xo - 5, y0, xo + 5, y0);

        snprintf(yLbl, sizeof(yLbl), "%d", v);
        painter->drawText(xo + 8, y0 + 7, yLbl);

        painter->drawLine(xo - 5, y1, xo + 5, y1);
        snprintf(yLbl, sizeof(yLbl), "%d", -v);
        painter->drawText(xo + 8, y1 + 5, yLbl);
        lasty0 = y0;
    }

    //Graph annotations
    painter->drawPath(penPath);
    char str[200];
    snprintf(str, sizeof(str), "max=%d  min=%d  mean=%" PRId64 "  n=%u/%zu",
             vMax,
             vMin,
             vMean,
             g_GraphStop - g_GraphStart,
             len
            );

    painter->drawText(20, annotationRect.bottom() - (48 - (12 * graphNum)), str);
}

void Plot::drawAnnotations(QRect annotationRect, QPainter *painter) {
    char *annotation;
    uint32_t length = 0;

    // Make a tiny black box at the bottom of the plot window
    QRect f(QPoint(80, annotationRect.bottom() - 59), QPoint(annotationRect.right(), annotationRect.bottom() - 74));
    painter->fillRect(f, BLACK);

    //Setup the scale string
    char scalestr[20] = {0};

    if (g_CursorScaleFactor != 1) {
        if (g_CursorScaleFactorUnit[0] == '\x00') {
            snprintf(scalestr, sizeof(scalestr), "[%2.2f] ", ((int32_t)(g_MarkerB.pos - g_MarkerA.pos)) / g_CursorScaleFactor);
        } else {
            snprintf(scalestr, sizeof(scalestr), "[%2.2f %s] ", ((int32_t)(g_MarkerB.pos - g_MarkerA.pos)) / g_CursorScaleFactor, g_CursorScaleFactorUnit);
        }
    }

    //Print the Graph Information
    char graphText[] = "@%u..%u  dt=%i %s zoom=%2.3f";
    length = ((sizeof(graphText)) + (sizeof(uint32_t) * 3) + sizeof(scalestr) + sizeof(float_t));

    annotation = (char *)calloc(1, length);

    snprintf(annotation, length, graphText,
             g_GraphStart,
             g_GraphStop,
             g_MarkerB.pos - g_MarkerA.pos,
             scalestr,
             g_GraphPixelsPerPoint
            );

    painter->setPen(GREEN);
    painter->drawText(82, annotationRect.bottom() - 62, annotation);

    //Print Grid Information if the grid is enabled
    if (g_PlotGridX > 0) {
        free(annotation);

        const char *gridLocked = (g_GridLocked ? "Locked" : "Unlocked");
        char gridText[] = "GridX=%lf  GridY=%lf (%s) GridXoffset=%lf";
        length = (sizeof(gridText) + (sizeof(double) * 3) + sizeof(gridLocked));

        annotation = (char *)calloc(1, length);

        snprintf(annotation, length, gridText,
                 g_DefaultGridX,
                 g_DefaultGridY,
                 gridLocked,
                 g_GridOffset
                );

        painter->setPen(WHITE);
        painter->drawText(800, annotationRect.bottom() - 62, annotation);
    }

    //Print the Marker Information
    char markerText[] = "Marker%s={Pos=%u Val=%d}";
    uint32_t pos = 0, loc = 375;
    painter->setPen(WHITE);

    if (g_MarkerA.pos > 0) {
        free(annotation);

        length = (sizeof(markerText) + (sizeof(uint32_t) * 3) + sizeof(" ") + 1);
        pos = g_MarkerA.pos;
        bool flag = false;
        size_t value;

        annotation = (char *)calloc(1, length);
        char *textA = (char *)calloc(1, length);

        strcat(textA, markerText);
        strcat(textA, " (%s%u)");

        if (g_GraphBuffer[pos] <= g_OperationBuffer[pos]) {
            flag = true;
            value = (g_OperationBuffer[pos] - g_GraphBuffer[pos]);
        } else {
            value = (g_GraphBuffer[pos] - g_OperationBuffer[pos]);
        }

        snprintf(annotation, length, textA,
                 "A",
                 pos,
                 g_GraphBuffer[pos],
                 flag ? "+" : "-",
                 value
                );

        painter->drawText(loc, annotationRect.bottom() - 48, annotation);

        free(textA);
    }

    if (g_MarkerB.pos > 0) {
        free(annotation);

        length = ((sizeof(markerText)) + (sizeof(uint32_t) * 2) + 1);
        pos = g_MarkerB.pos;

        annotation = (char *)calloc(1, length);

        snprintf(annotation, length, markerText,
                 "B",
                 pos,
                 g_GraphBuffer[pos]
                );

        painter->drawText(loc, annotationRect.bottom() - 36, annotation);
    }

    if (g_MarkerC.pos > 0) {
        free(annotation);

        length = ((sizeof(markerText)) + (sizeof(uint32_t) * 2) + 1);
        pos = g_MarkerC.pos;

        annotation = (char *)calloc(1, length);

        snprintf(annotation, length, markerText,
                 "C",
                 pos,
                 g_GraphBuffer[pos]
                );

        painter->drawText(loc, annotationRect.bottom() - 24, annotation);
    }

    if (g_MarkerD.pos > 0) {
        free(annotation);

        length = ((sizeof(markerText)) + (sizeof(uint32_t) * 2) + 1);
        pos = g_MarkerD.pos;

        annotation = (char *)calloc(1, length);

        snprintf(annotation, length, markerText,
                 "D",
                 pos,
                 g_GraphBuffer[pos]
                );

        painter->drawText(loc, annotationRect.bottom() - 12, annotation);
    }

    free(annotation);
}

void Plot::plotGridLines(QPainter *painter, QRect r) {

    // set g_GridOffset
    if (g_PlotGridX <= 0) {
        return;
    }

    double offset = g_GridOffset;
    if (g_GridLocked && g_PlotGridX) {
        offset = g_GridOffset + g_PlotGridX - fmod(g_GraphStart, g_PlotGridX);
    } else if (g_GridLocked == false && g_GraphStart > 0 && g_PlotGridX) {
        offset = g_PlotGridX - fmod(g_GraphStart - offset, g_PlotGridX) + g_GraphStart - unlockStart;
    }

    offset = fmod(offset, g_PlotGridX);

    if (offset < 0) {
        offset += g_PlotGridX;
    }

    double i;
    double grid_delta_x = g_PlotGridX * g_GraphPixelsPerPoint;
    int grid_delta_y = g_PlotGridY;

    if ((g_PlotGridX > 0) && ((g_PlotGridX * g_GraphPixelsPerPoint) > 1)) {
        for (i = (offset * g_GraphPixelsPerPoint); i < r.right(); i += grid_delta_x) {
            painter->drawLine(r.left() + i, r.top(), r.left() + i, r.bottom());
        }
    }

    if (g_PlotGridY > 0) {
        for (i = 0; yCoordOf(i, r, gs_absVMax) > r.top(); i += grid_delta_y) {
            // line above mid
            painter->drawLine(r.left(), yCoordOf(i, r, gs_absVMax), r.right(), yCoordOf(i, r, gs_absVMax));
            // line below mid
            painter->drawLine(r.left(), yCoordOf(-i, r, gs_absVMax), r.right(), yCoordOf(-i, r, gs_absVMax));
        }
    }
}

void Plot::plotOperations(int *buffer, size_t len, QPainter *painter, QRect plotRect) {
    if (len == 0) {
        return;
    }

    QPainterPath penPath;
    int32_t x = xCoordOf(g_GraphStart, plotRect), prevX = 0;
    int32_t y = yCoordOf(buffer[g_GraphStart], plotRect, gs_absVMax), prevY = 0;
    int32_t current = 0, prev = 0;
    bool changed = false;

    for (uint32_t pos = g_GraphStart; pos < len && xCoordOf(pos, plotRect) < plotRect.right(); pos++) {
        //Store the previous x and y values to move the pen to if we need to draw a line
        prevX = x;
        prevY = y;

        changed = false;
        x = xCoordOf(pos, plotRect);
        prev = current;
        current = buffer[pos];
        y = yCoordOf(current, plotRect, gs_absVMax);

        //We only want to graph changes between the Graph Buffer and the Operation Buffer
        if (current == g_GraphBuffer[pos]) {
            //If this point is the same, but the last point is different, we want to plot that line
            //as well
            if ((pos == 0) || (prev == g_GraphBuffer[pos - 1])) {
                continue;
            }
        } else {
            changed = true;
        }

        penPath.moveTo(prevX, prevY); //Move the pen
        penPath.lineTo(x, y); //Draw the line from the previous coords to the new ones

        //Only draw a white square if the point is different
        if (g_GraphPixelsPerPoint > 10 && changed) {
            QRect point(QPoint(x - 3, y - 3), QPoint(x + 3, y + 3));
            painter->fillRect(point, WHITE);
        }
    }

    painter->setPen(CITRON);
    painter->drawPath(penPath);
}

#define HEIGHT_INFO 60
#define WIDTH_AXES 80

void Plot::paintEvent(QPaintEvent *event) {
    QPainter painter(this);
    QBrush brush(GREEN);
    QPen pen(GREEN);

    painter.setFont(QFont("Courier New", 10));

    QRect plotRect(WIDTH_AXES, 0, width() - WIDTH_AXES, height() - HEIGHT_INFO);
    QRect infoRect(0, height() - HEIGHT_INFO, width(), HEIGHT_INFO);
    PageWidth = plotRect.width() / g_GraphPixelsPerPoint;

    //Grey background
    painter.fillRect(rect(), GRAY60);
    //Black foreground
    painter.fillRect(plotRect, BLACK);

    //init graph variables
    setMaxAndStart(g_GraphBuffer, g_GraphTraceLen, plotRect);
    //appendMax(g_OperationBuffer, g_GraphTraceLen, plotRect);

    // center line
    int zeroHeight = plotRect.top() + (plotRect.bottom() - plotRect.top()) / 2;
    painter.setPen(GRAY100);
    painter.drawLine(plotRect.left(), zeroHeight, plotRect.right(), zeroHeight);
    // plot X and Y grid lines
    plotGridLines(&painter, plotRect);

    //Start painting graph
    PlotGraph(g_GraphBuffer, g_GraphTraceLen, plotRect, infoRect, &painter, 0);
    if (g_DemodBufferLen > 8) {
        PlotDemod(g_DemodBuffer, g_DemodBufferLen, plotRect, infoRect, &painter, 2, g_DemodStartIdx);
    }

    //Plot the Operation Overlay
    //plotOperations(g_OperationBuffer, g_GraphTraceLen, &painter, plotRect);

    //Plot the Overlay
    if (g_useOverlays) {
        //init graph variables
        setMaxAndStart(g_OverlayBuffer, g_GraphTraceLen, plotRect);
        PlotGraph(g_OverlayBuffer, g_GraphTraceLen, plotRect, infoRect, &painter, 1);
    }
    // End graph drawing

    //Draw the markers
    if (g_TempMarkerSize > 0) {
        for (int i = 0; i < g_TempMarkerSize; i++) {
            draw_marker(g_TempMarkers[i], plotRect, GRAY100, &painter);
        }
    }

    draw_marker(g_MarkerA, plotRect, YELLOW, &painter);
    draw_marker(g_MarkerB, plotRect, PINK, &painter);
    draw_marker(g_MarkerC, plotRect, ORANGE, &painter);
    draw_marker(g_MarkerD, plotRect, LIGHTBLUE, &painter);

    //Draw annotations
    drawAnnotations(infoRect, &painter);

    if (startMaxOld != startMax) {
        emit startMaxChanged(startMax);
    }
    startMaxOld = startMax;

    if (g_GraphStart != g_GraphStart_old) {
        emit graphStartChanged(g_GraphStart);
    }
    g_GraphStart_old = g_GraphStart;
}

void Plot::draw_marker(marker_t marker, QRect plotRect, QColor color, QPainter *painter) {
    painter->setPen(color);

    //If the marker is outside the buffer length, reset
    if (marker.pos > g_GraphTraceLen) {
        marker.pos = 0;
    }

    //Make sure the marker is inside the current plot view to render
    if (marker.pos > g_GraphStart && xCoordOf(marker.pos, plotRect) < plotRect.right()) {
        painter->drawLine(xCoordOf(marker.pos, plotRect), plotRect.top(), xCoordOf(marker.pos, plotRect), plotRect.bottom());

        if (strlen(marker.label) > 0) {
            painter->drawText(xCoordOf(marker.pos, plotRect) + 1, plotRect.top() + 12, marker.label);
        }
    }
}

Plot::Plot(QWidget *parent) : QWidget(parent), g_GraphPixelsPerPoint(1) {
    //Need to set this, otherwise we don't receive keypress events
    setFocusPolicy(Qt::StrongFocus);
    resize(400, 200);

    QPalette palette(QColor(0, 0, 0, 0));
    palette.setColor(QPalette::WindowText, WHITE);
    palette.setColor(QPalette::Text, WHITE);
    palette.setColor(QPalette::Button, GRAY100);
    setPalette(palette);
    setAutoFillBackground(true);

    g_MarkerA.pos = 0;
    g_MarkerB.pos = 0;
    g_MarkerC.pos = 0;
    g_MarkerD.pos = 0;
    g_GraphStart = 0;
    g_GraphStop = 0;

    setWindowTitle(tr("Sliders"));
    master = parent;
}

void Plot::closeEvent(QCloseEvent *event) {
    event->ignore();
    this->hide();
    g_useOverlays = false;
}

// every 4 steps the zoom doubles (or halves)
#define ZOOM_STEP (1.189207)
// limit zoom to 32 times in either direction
#define ZOOM_LIMIT (32)

void Plot::Zoom(double factor, uint32_t refX) {
    double g_GraphPixelsPerPointNew = g_GraphPixelsPerPoint * factor;

    if (factor >= 1) { // Zoom in
        if (g_GraphPixelsPerPointNew <= ZOOM_LIMIT) {
            g_GraphPixelsPerPoint = g_GraphPixelsPerPointNew;
            if (refX > g_GraphStart) {
                g_GraphStart += (refX - g_GraphStart) - ((refX - g_GraphStart) / factor);
            }
        }
    } else {          // Zoom out
        if (g_GraphPixelsPerPointNew >= (1.0 / ZOOM_LIMIT)) {
            g_GraphPixelsPerPoint = g_GraphPixelsPerPointNew;
            // shift graph towards refX when zooming out
            if (refX > g_GraphStart) {
                if (g_GraphStart >= ((refX - g_GraphStart) / factor) - (refX - g_GraphStart)) {
                    g_GraphStart -= ((refX - g_GraphStart) / factor) - (refX - g_GraphStart);
                } else {
                    g_GraphStart = 0;
                }
            }
        }
    }
}

void Plot::MoveTo(uint32_t pos) {
    if (g_GraphTraceLen == 0) {
        return;
    }

    g_GraphStart = pos;

    QObject *signalSender = sender();
    if (signalSender != nullptr && signalSender != this) {
        // Update if it's triggered by a signal from other object
        this->update();
    }
}

void Plot::MoveTo(int pos) {
    MoveTo((uint32_t)((pos >= 0) ? pos : 0));
    // sender() is still valid in the inner call
}

void Plot::Move(int offset) {
    if (g_GraphTraceLen == 0) {
        return;
    }

    if (offset > 0) { // Move right
        if (g_GraphPixelsPerPoint < 20) {
            g_GraphStart += offset;
        } else {
            g_GraphStart++;
        }
    } else { // Move left
        if (g_GraphPixelsPerPoint < 20) {
            if (g_GraphStart >= (uint) - offset) {
                g_GraphStart += offset;
            } else {
                g_GraphStart = 0;
            }
        } else {
            if (g_GraphStart > 0) {
                g_GraphStart--;
            }
        }
    }
}

void Plot::Trim(void) {
    uint32_t lref, rref;
    if ((g_MarkerA.pos == 0) || (g_MarkerB.pos == 0)) { // if we don't have both cursors set
        lref = g_GraphStart;
        rref = g_GraphStop;
        if (g_MarkerA.pos >= lref) {
            g_MarkerA.pos -= lref;
        } else {
            g_MarkerA.pos = 0;
        }
        if (g_MarkerB.pos >= lref) {
            g_MarkerB.pos -= lref;
        } else {
            g_MarkerB.pos = 0;
        }
    } else {

        lref = g_MarkerA.pos < g_MarkerB.pos ? g_MarkerA.pos : g_MarkerB.pos;
        rref = g_MarkerA.pos < g_MarkerB.pos ? g_MarkerB.pos : g_MarkerA.pos;

        // g_GraphPixelsPerPoint must remain a power of ZOOM_STEP
        double GPPPtarget = g_GraphPixelsPerPoint * (g_GraphStop - g_GraphStart) / (rref - lref);

        while (g_GraphPixelsPerPoint < GPPPtarget) {
            g_GraphPixelsPerPoint *= ZOOM_STEP;
        }

        g_GraphPixelsPerPoint /= ZOOM_STEP;
        g_MarkerA.pos -= lref;
        g_MarkerB.pos -= lref;
    }
    g_DemodStartIdx -= lref;

    for (uint32_t i = lref; i < rref; ++i) {
        g_GraphBuffer[i - lref] = g_GraphBuffer[i];
    }

    g_GraphTraceLen = rref - lref;
    g_GraphStart = 0;
}

void Plot::wheelEvent(QWheelEvent *event) {
    // event->delta()
    //  120 => shift right 5%
    // -120 => shift left 5%
    const float move_offset = 0.05;
    // -120+shift => zoom in  (5 times = *2)
    //  120+shift => zoom out (5 times = /2)
#if QT_VERSION >= 0x050d00
    // event->position doesn't exist in QT5.12.8, both exist in 5.14.2 and event->x doesn't exist in 5.15.0
    uint32_t x = event->position().x();
    // event->angleDelta doesn't exist in QT4, both exist in 5.12.8 and 5.14.2 and event->delta doesn't exist in 5.15.0
    float delta = -event->angleDelta().y();
#else
    uint32_t x = event->x();
    float delta = -event->delta();
#endif
    if (event->modifiers() & (Qt::ShiftModifier | Qt::ControlModifier)) {
        x -= WIDTH_AXES;
        x = (int)(x / g_GraphPixelsPerPoint);
        x += g_GraphStart;

        if (delta < 0) {
            Zoom(ZOOM_STEP, x);
        } else {
            Zoom(1.0 / ZOOM_STEP, x);
        }

    } else {
        Move(PageWidth * delta * move_offset / 120);
    }
    this->update();
}

void Plot::mouseMoveEvent(QMouseEvent *event) {
    int x = event->x();

    //Only run the marker place code if a mouse button is pressed
    if ((event->buttons() & Qt::LeftButton) || (event->buttons() & Qt::RightButton)) {
        x -= WIDTH_AXES;
        x = (int)(x / g_GraphPixelsPerPoint);
        x += g_GraphStart;

        if (x > (int)g_GraphTraceLen)   x = 0; // Set to 0 if the number is stupidly big
        else if (x < (int)g_GraphStart) x = (int)g_GraphStart; // Bounds checking for the start of the Graph Window
        else if (x > (int)g_GraphStop)  x = (int)g_GraphStop; // Bounds checking for the end of the Graph Window

        if ((event->buttons() & Qt::LeftButton)) { // True for left click, false otherwise
            g_MarkerA.pos = x;
        } else {
            g_MarkerB.pos = x;
        }
    }

    this->update();
}

void Plot::keyPressEvent(QKeyEvent *event) {
    uint32_t offset; // Left/right movement offset (in sample size)

    if (event->modifiers() & Qt::ShiftModifier) {
        if (g_PlotGridX) {
            offset = PageWidth - fmod(PageWidth, g_PlotGridX);
        } else {
            offset = PageWidth;
        }
    } else {
        if (event->modifiers() & Qt::ControlModifier) {
            offset = 1;
        } else {
            offset = int(ZOOM_LIMIT / g_GraphPixelsPerPoint);
        }
    }

    switch (event->key()) {
        case Qt::Key_Down:
            if (event->modifiers() & Qt::ShiftModifier) {
                if (event->modifiers() & Qt::ControlModifier) {
                    Zoom(ZOOM_STEP, g_MarkerB.pos);
                } else {
                    Zoom(ZOOM_STEP * 2, g_MarkerB.pos);
                }
            } else {
                if (event->modifiers() & Qt::ControlModifier) {
                    Zoom(ZOOM_STEP, g_MarkerA.pos);
                } else {
                    Zoom(ZOOM_STEP * 2, g_MarkerA.pos);
                }
            }
            break;

        case Qt::Key_Up:
            if (event->modifiers() & Qt::ShiftModifier) {
                if (event->modifiers() & Qt::ControlModifier) {
                    Zoom(1.0 / ZOOM_STEP, g_MarkerB.pos);
                } else {
                    Zoom(1.0 / (ZOOM_STEP * 2), g_MarkerB.pos);
                }
            } else {
                if (event->modifiers() & Qt::ControlModifier) {
                    Zoom(1.0 / ZOOM_STEP, g_MarkerA.pos);
                } else {
                    Zoom(1.0 / (ZOOM_STEP * 2), g_MarkerA.pos);
                }
            }
            break;

        case Qt::Key_Right:
            Move(offset);
            break;

        case Qt::Key_Left:
            Move(-offset);
            break;

        case Qt::Key_Greater:
            g_DemodStartIdx += 1;
            break;

        case Qt::Key_Less:
            g_DemodStartIdx -= 1;
            break;

        case Qt::Key_G:
            if (g_PlotGridX || g_PlotGridY) {
                g_PlotGridX = 0;
                g_PlotGridY = 0;
            } else {
                if (g_DefaultGridX < 0) {
                    g_DefaultGridX = 64;
                }

                if (g_DefaultGridY < 0) {
                    g_DefaultGridY = 0;
                }

                g_PlotGridX = g_DefaultGridX;
                g_PlotGridY = g_DefaultGridY;
            }
            break;

        case Qt::Key_H: {
            uint8_t old_printAndLog = g_printAndLog;
            g_printAndLog &= PRINTANDLOG_PRINT;
            PrintAndLogEx(NORMAL, "\n\n" _CYAN_("PLOT window keystrokes and mouse events"));
            PrintAndLogEx(NORMAL, "\n" _GREEN_("Move:"));
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("Home") "/" _RED_("End"), "Move to the start/end of the graph");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, _YELLOW_("Mouse wheel"), "Move left/right");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("Left") "/" _RED_("Right"), "Move left/right");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, " + " _RED_("Ctrl"), "... by 1 sample");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, " + " _RED_("Shift"), "... by 1 window");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("PgUp") "/" _RED_("PgDown"), "Move left/right by 1 window");
            PrintAndLogEx(NORMAL, "\n" _GREEN_("Zoom:"));
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("Shift") " + " _YELLOW_("Mouse wheel"), "Zoom in/out around mouse cursor");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("Down") "/" _RED_("Up"), "Zoom in/out around yellow marker");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, " + " _RED_("Ctrl"), "... with smaller increment");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, " + " _RED_("Shift"), "... around purple marker");
            PrintAndLogEx(NORMAL, "\n" _GREEN_("Trim:"));
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, _RED_("t"), "Trim data on window or on markers (if defined)");
            PrintAndLogEx(NORMAL, "\n" _GREEN_("Grid and demod:"));
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, _RED_("g"), "Toggle grid and demodulation plot display");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, _RED_("l"), "Toggle lock grid relative to samples");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("< ") "/" _RED_(" >"), "Move demodulation left/right relative to samples");
            PrintAndLogEx(NORMAL, "\n" _GREEN_("Misc:"));
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, _YELLOW_("Left mouse click"), "Set yellow marker");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, _YELLOW_("Right mouse click"), "Set purple marker");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("[ ") "/" _RED_(" ]"), "Move yellow marker left/right by 1 sample");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("{ ") "/" _RED_(" }"), "Move purple marker left/right by 1 sample");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, " + " _RED_("Ctrl"), "... by 5 samples");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("= ") "/" _RED_(" -"), "Add/Subtract to the plot point (Operation Buffer) over the yellow marker by 1");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, " + " _RED_("Ctrl"), "... by 5");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9 + 9, _RED_("+ ") "/" _RED_(" _"), "Add/Subtract to the plot point (Graph Buffer) over the yellow marker by 1");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, " + " _RED_("Ctrl"), "... by 5");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, _RED_("h"), "Show this help");
            PrintAndLogEx(NORMAL, "    %-*s%s", 25 + 9, _RED_("q"), "Close plot window");
            g_printAndLog = old_printAndLog;
            break;
        }
        case Qt::Key_L:
            g_GridLocked = !g_GridLocked;

            if (g_GridLocked) {
                g_GridOffset += (g_GraphStart - unlockStart);
            } else {
                unlockStart = g_GraphStart;
            }
            break;

        case Qt::Key_Q:
            master->hide();
            break;

        case Qt::Key_T:
            Trim();
            break;

        case Qt::Key_Home:
            g_GraphStart = 0;
            break;

        case Qt::Key_End:
            g_GraphStart = startMax;
            break;

        case Qt::Key_PageUp:
            if (g_GraphStart >= PageWidth) {
                g_GraphStart -= PageWidth;
            } else {
                g_GraphStart = 0;
            }
            break;

        case Qt::Key_PageDown:
            g_GraphStart += PageWidth;
            if (g_GraphStart > startMax)
                g_GraphStart = startMax;
            break;

        case Qt::Key_Equal:
            if (event->modifiers() & Qt::ControlModifier) {
                g_OperationBuffer[g_MarkerA.pos] += 5;
            } else {
                g_OperationBuffer[g_MarkerA.pos] += 1;
            }

            RepaintGraphWindow();
            break;

        case Qt::Key_Minus:
            if (event->modifiers() & Qt::ControlModifier) {
                g_OperationBuffer[g_MarkerA.pos] -= 5;
            } else {
                g_OperationBuffer[g_MarkerA.pos] -= 1;
            }

            RepaintGraphWindow();
            break;

        case Qt::Key_Plus:
            if (event->modifiers() & Qt::ControlModifier) {
                g_GraphBuffer[g_MarkerA.pos] += 5;
            } else {
                g_GraphBuffer[g_MarkerA.pos] += 1;
            }

            RepaintGraphWindow();
            break;

        case Qt::Key_Underscore:
            if (event->modifiers() & Qt::ControlModifier) {
                g_GraphBuffer[g_MarkerA.pos] -= 5;
            } else {
                g_GraphBuffer[g_MarkerA.pos] -= 1;
            }

            RepaintGraphWindow();
            break;

        case Qt::Key_BracketLeft: {
            if (event->modifiers() & Qt::ControlModifier) {
                g_MarkerA.pos -= 5;
            } else {
                g_MarkerA.pos -= 1;
            }

            if ((g_MarkerA.pos >= g_GraphStop) || (g_MarkerA.pos <= g_GraphStart)) {
                uint32_t halfway = PageWidth / 2;

                if ((g_MarkerA.pos - halfway) > g_GraphTraceLen) {
                    g_GraphStart = 0;
                }  else {
                    g_GraphStart = g_MarkerA.pos - halfway;
                }
            }

            if (g_MarkerA.pos < g_GraphStart) {
                g_MarkerA.pos = g_GraphStart;
            }

            RepaintGraphWindow();
            break;
        }

        case Qt::Key_BracketRight: {
            if (event->modifiers() & Qt::ControlModifier) {
                g_MarkerA.pos += 5;
            } else {
                g_MarkerA.pos += 1;
            }

            if ((g_MarkerA.pos >= g_GraphStop) || (g_MarkerA.pos <= g_GraphStart)) {
                uint32_t halfway = PageWidth / 2;

                if ((g_MarkerA.pos + halfway) >= g_GraphTraceLen) {
                    g_GraphStart = g_GraphTraceLen - halfway;
                } else {
                    g_GraphStart = g_MarkerA.pos - halfway;
                }
            }

            if (g_MarkerA.pos >= g_GraphTraceLen) {
                g_MarkerA.pos = g_GraphTraceLen;
            }

            RepaintGraphWindow();
            break;
        }

        case Qt::Key_BraceLeft:
            if (event->modifiers() & Qt::ControlModifier) {
                g_MarkerB.pos -= 5;
            } else {
                g_MarkerB.pos -= 1;
            }

            if (g_MarkerB.pos < g_GraphStart) {
                g_MarkerB.pos = g_GraphStart;
            }

            RepaintGraphWindow();
            break;

        case Qt::Key_BraceRight:
            if (event->modifiers() & Qt::ControlModifier) {
                g_MarkerB.pos += 5;
            } else {
                g_MarkerB.pos += 1;
            }

            if (g_MarkerB.pos >= g_GraphTraceLen) {
                g_MarkerB.pos = g_GraphTraceLen;
            }

            RepaintGraphWindow();
            break;

        default:
            QWidget::keyPressEvent(event);
            return;
            break;
    }

    this->update();
}
