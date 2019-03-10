//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// GUI (QT)
//-----------------------------------------------------------------------------
#include "proxguiqt.h"

#include <stdbool.h>
#include <iostream>
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
#include "proxgui.h"
#include <QtGui>

extern "C" {
#include "util_darwin.h"
}

bool g_useOverlays = false;
int g_absVMax = 0;
int startMax;
int PageWidth;
int unlockStart = 0;

void ProxGuiQT::ShowGraphWindow(void) {
    emit ShowGraphWindowSignal();
}

void ProxGuiQT::RepaintGraphWindow(void) {
    emit RepaintGraphWindowSignal();
}

void ProxGuiQT::HideGraphWindow(void) {
    emit HideGraphWindowSignal();
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

    connect(this, SIGNAL(ShowGraphWindowSignal()), this, SLOT(_ShowGraphWindow()));
    connect(this, SIGNAL(RepaintGraphWindowSignal()), this, SLOT(_RepaintGraphWindow()));
    connect(this, SIGNAL(HideGraphWindowSignal()), this, SLOT(_HideGraphWindow()));
    connect(this, SIGNAL(ExitSignal()), this, SLOT(_Exit()));

    //start proxmark thread after starting event loop
    QTimer::singleShot(200, this, SLOT(_StartProxmarkThread()));

#if defined(__MACH__) && defined(__APPLE__)
    //Prevent the terminal from loosing focus during launch by making the client unfocusable
    makeUnfocusable();
#endif


    plotapp->exec();
}

ProxGuiQT::ProxGuiQT(int argc, char **argv, WorkerThread *wthread) : plotapp(NULL), plotwidget(NULL),
    argc(argc), argv(argv), proxmarkThread(wthread) {
}

ProxGuiQT::~ProxGuiQT(void) {
    if (plotapp) {
        plotapp->quit();
        plotapp = NULL;
    }
}

//--------------------
void ProxWidget::applyOperation() {
    //printf("ApplyOperation()");
    save_restoreGB(GRAPH_SAVE);
    memcpy(GraphBuffer, s_Buff, sizeof(int) * GraphTraceLen);
    RepaintGraphWindow();
}
void ProxWidget::stickOperation() {
    save_restoreGB(GRAPH_RESTORE);
    //printf("stickOperation()");
}
void ProxWidget::vchange_autocorr(int v) {
    int ans = AutoCorrelate(GraphBuffer, s_Buff, GraphTraceLen, v, true, false);
    if (g_debugMode) printf("vchange_autocorr(w:%d): %d\n", v, ans);
    g_useOverlays = true;
    RepaintGraphWindow();
}
void ProxWidget::vchange_askedge(int v) {
    //extern int AskEdgeDetect(const int *in, int *out, int len, int threshold);
    int ans = AskEdgeDetect(GraphBuffer, s_Buff, GraphTraceLen, v);
    if (g_debugMode) printf("vchange_askedge(w:%d)%d\n", v, ans);
    g_useOverlays = true;
    RepaintGraphWindow();
}
void ProxWidget::vchange_dthr_up(int v) {
    int down = opsController->horizontalSlider_dirthr_down->value();
    directionalThreshold(GraphBuffer, s_Buff, GraphTraceLen, v, down);
    //printf("vchange_dthr_up(%d)", v);
    g_useOverlays = true;
    RepaintGraphWindow();
}
void ProxWidget::vchange_dthr_down(int v) {
    //printf("vchange_dthr_down(%d)", v);
    int up = opsController->horizontalSlider_dirthr_up->value();
    directionalThreshold(GraphBuffer, s_Buff, GraphTraceLen, v, up);
    g_useOverlays = true;
    RepaintGraphWindow();
}
ProxWidget::ProxWidget(QWidget *parent, ProxGuiQT *master) : QWidget(parent) {
    this->master = master;
    resize(800, 400);

    // Setup the controller widget
    controlWidget = new QWidget();
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

    // Set up the plot widget, which does the actual plotting
    plot = new Plot(this);
    QVBoxLayout *layout = new QVBoxLayout;
    layout->addWidget(plot);
    setLayout(layout);
    show(); // places the window on the screen.

    // Move controller widget below plot
    controlWidget->move(x(), y() + frameSize().height());
    controlWidget->resize(size().width(), 200);
    controlWidget->show();
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
    controlWidget->show();
    plot->show();
}

//----------- Plotting

int Plot::xCoordOf(int i, QRect r) {
    return r.left() + (int)((i - GraphStart) * GraphPixelsPerPoint);
}

int Plot::yCoordOf(int v, QRect r, int maxVal) {
    int z = (r.bottom() - r.top()) / 2;
    if (maxVal == 0) ++maxVal;
    return -(z * v) / maxVal + z;
}

int Plot::valueOf_yCoord(int y, QRect r, int maxVal) {
    int z = (r.bottom() - r.top()) / 2;
    return (y - z) * maxVal / z;
}

static const QColor GREEN = QColor(100, 255, 100);
static const QColor RED   = QColor(255, 100, 100);
static const QColor BLUE  = QColor(100, 100, 255);
static const QColor GRAY = QColor(240, 240, 240);

QColor Plot::getColor(int graphNum) {
    switch (graphNum) {
        case 0:
            return GREEN;  //Green
        case 1:
            return RED;    //Red
        case 2:
            return BLUE;   //Blue
        default:
            return GRAY;  //Gray
    }
}

void Plot::setMaxAndStart(int *buffer, int len, QRect plotRect) {
    if (len == 0) return;
    startMax = (len - (int)((plotRect.right() - plotRect.left() - 40) / GraphPixelsPerPoint));
    if (startMax < 0) {
        startMax = 0;
    }
    if (GraphStart > startMax) {
        GraphStart = startMax;
    }
    if (GraphStart > len) return;
    int vMin = INT_MAX, vMax = INT_MIN, v = 0;
    int sample_index = GraphStart ;
    for (; sample_index < len && xCoordOf(sample_index, plotRect) < plotRect.right() ; sample_index++) {

        v = buffer[sample_index];
        if (v < vMin) vMin = v;
        if (v > vMax) vMax = v;
    }

    g_absVMax = 0;
    if (fabs((double) vMin) > g_absVMax) g_absVMax = (int)fabs((double) vMin);
    if (fabs((double) vMax) > g_absVMax) g_absVMax = (int)fabs((double) vMax);
    g_absVMax = (int)(g_absVMax * 1.25 + 1);
}

void Plot::PlotDemod(uint8_t *buffer, size_t len, QRect plotRect, QRect annotationRect, QPainter *painter, int graphNum, int plotOffset) {
    if (len == 0 || PlotGridX <= 0) return;
    //clock_t begin = clock();
    QPainterPath penPath;

    int grid_delta_x = PlotGridX;
    int first_delta_x = grid_delta_x; //(plotOffset > 0) ? PlotGridX : (PlotGridX +);
    if (GraphStart > plotOffset) first_delta_x -= (GraphStart - plotOffset);
    int DemodStart = GraphStart;
    if (plotOffset > GraphStart) DemodStart = plotOffset;

    int BitStart = 0;
    // round down
    if (DemodStart - plotOffset > 0) BitStart = (int)(((DemodStart - plotOffset) + (PlotGridX - 1)) / PlotGridX) - 1;
    first_delta_x += BitStart * PlotGridX;
    if (BitStart > (int)len) return;
    int delta_x = 0;
    int v = 0;
    //printf("first_delta_x %i, grid_delta_x %i, DemodStart %i, BitStart %i\n",first_delta_x,grid_delta_x,DemodStart, BitStart);

    painter->setPen(getColor(graphNum));
    char str[5];
    int absVMax = (int)(100 * 1.05 + 1);
    int x = xCoordOf(DemodStart, plotRect);
    int y = yCoordOf((buffer[BitStart] * 200 - 100) * -1, plotRect, absVMax);
    penPath.moveTo(x, y);
    delta_x = 0;
    int clk = first_delta_x;
    for (int i = BitStart; i < (int)len && xCoordOf(delta_x + DemodStart, plotRect) < plotRect.right(); i++) {
        for (int ii = 0; ii < (clk) && i < (int)len && xCoordOf(DemodStart + delta_x + ii, plotRect) < plotRect.right() ; ii++) {
            x = xCoordOf(DemodStart + delta_x + ii, plotRect);
            v = buffer[i] * 200 - 100;

            y = yCoordOf(v, plotRect, absVMax);

            penPath.lineTo(x, y);

            if (GraphPixelsPerPoint > 10) {
                QRect f(QPoint(x - 3, y - 3), QPoint(x + 3, y + 3));
                painter->fillRect(f, QColor(100, 255, 100));
            }
            if (ii == (int)clk / 2) {
                //print label
                sprintf(str, "%u", buffer[i]);
                painter->drawText(x - 8, y + ((buffer[i] > 0) ? 18 : -6), str);
            }
        }
        delta_x += clk;
        clk = grid_delta_x;
    }

    // Graph annotations
    painter->drawPath(penPath);
}

void Plot::PlotGraph(int *buffer, int len, QRect plotRect, QRect annotationRect, QPainter *painter, int graphNum) {
    if (len == 0) return;
    // clock_t begin = clock();
    QPainterPath penPath;
    int vMin = INT_MAX, vMax = INT_MIN, vMean = 0, v = 0, i = 0;
    int x = xCoordOf(GraphStart, plotRect);
    int y = yCoordOf(buffer[GraphStart], plotRect, g_absVMax);
    penPath.moveTo(x, y);
    for (i = GraphStart; i < len && xCoordOf(i, plotRect) < plotRect.right(); i++) {

        x = xCoordOf(i, plotRect);
        v = buffer[i];

        y = yCoordOf(v, plotRect, g_absVMax);

        penPath.lineTo(x, y);

        if (GraphPixelsPerPoint > 10) {
            QRect f(QPoint(x - 3, y - 3), QPoint(x + 3, y + 3));
            painter->fillRect(f, QColor(100, 255, 100));
        }
        // catch stats
        if (v < vMin) vMin = v;
        if (v > vMax) vMax = v;
        vMean += v;
    }
    vMean /= (i - GraphStart);

    painter->setPen(getColor(graphNum));

    // Draw y-axis
    int xo = 5 + (graphNum * 40);
    painter->drawLine(xo, plotRect.top(), xo, plotRect.bottom());

    int vMarkers = (g_absVMax - (g_absVMax % 10)) / 5;
    int minYDist = 40; // Minimum pixel-distance between markers

    char yLbl[20];

    int n = 0;
    int lasty0 = 65535;

    for (v = vMarkers; yCoordOf(v, plotRect, g_absVMax) > plotRect.top() && n < 20; v += vMarkers, n++) {
        int y0 = yCoordOf(v, plotRect, g_absVMax);
        int y1 = yCoordOf(-v, plotRect, g_absVMax);

        if (lasty0 - y0 < minYDist) continue;

        painter->drawLine(xo - 5, y0, xo + 5, y0);

        sprintf(yLbl, "%d", v);
        painter->drawText(xo + 8, y0 + 7, yLbl);

        painter->drawLine(xo - 5, y1, xo + 5, y1);
        sprintf(yLbl, "%d", -v);
        painter->drawText(xo + 8, y1 + 5, yLbl);
        lasty0 = y0;
    }

    //Graph annotations
    painter->drawPath(penPath);
    char str[200];
    sprintf(str, "max=%d  min=%d  mean=%d  n=%d/%d  CursorAVal=[%d]  CursorBVal=[%d]",
            vMax, vMin, vMean, i, len, buffer[CursorAPos], buffer[CursorBPos]);
    painter->drawText(20, annotationRect.bottom() - 23 - 20 * graphNum, str);

    //clock_t end = clock();
    //double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    //printf("Plot time %f\n", elapsed_secs);
}

void Plot::plotGridLines(QPainter *painter, QRect r) {

    // set GridOffset
    if (PlotGridX <= 0) return;

    int offset = GridOffset;
    if (GridLocked && PlotGridX) {
        offset = GridOffset + PlotGridX - (GraphStart % PlotGridX);
    } else if (!GridLocked && GraphStart > 0 && PlotGridX) {
        offset = PlotGridX - ((GraphStart - offset) % PlotGridX) + GraphStart - unlockStart;
    }
    offset %= PlotGridX;
    if (offset < 0) offset += PlotGridX;

    int i;
    int grid_delta_x = (int)(PlotGridX * GraphPixelsPerPoint);
    int grid_delta_y = PlotGridY;

    if ((PlotGridX > 0) && ((PlotGridX * GraphPixelsPerPoint) > 1)) {
        for (i = (offset * GraphPixelsPerPoint); i < r.right(); i += grid_delta_x) {
            painter->drawLine(r.left() + i, r.top(), r.left() + i, r.bottom());
        }
    }

    if (PlotGridY > 0) {
        for (i = 0; yCoordOf(i, r, g_absVMax) > r.top(); i += grid_delta_y) {
            // line above mid
            painter->drawLine(r.left(), yCoordOf(i, r, g_absVMax), r.right(), yCoordOf(i, r, g_absVMax));
            // line below mid
            painter->drawLine(r.left(), yCoordOf(-i, r, g_absVMax), r.right(), yCoordOf(-i, r, g_absVMax));
        }
    }
}

#define HEIGHT_INFO 60
#define WIDTH_AXES 80

void Plot::paintEvent(QPaintEvent *event) {
    QPainter painter(this);
    QBrush brush(QColor(100, 255, 100));
    QPen pen(QColor(100, 255, 100));

    painter.setFont(QFont("Courier New", 10));

    if (GraphStart < 0)
        GraphStart = 0;

    if (CursorAPos > GraphTraceLen)
        CursorAPos = 0;
    if (CursorBPos > GraphTraceLen)
        CursorBPos = 0;
    if (CursorCPos > GraphTraceLen)
        CursorCPos = 0;
    if (CursorDPos > GraphTraceLen)
        CursorDPos = 0;

    QRect plotRect(WIDTH_AXES, 0, width() - WIDTH_AXES, height() - HEIGHT_INFO);
    QRect infoRect(0, height() - HEIGHT_INFO, width(), HEIGHT_INFO);

    //Grey background
    painter.fillRect(rect(), QColor(60, 60, 60));
    //Black foreground
    painter.fillRect(plotRect, QColor(0, 0, 0));

    //init graph variables
    setMaxAndStart(GraphBuffer, GraphTraceLen, plotRect);

    // center line
    int zeroHeight = plotRect.top() + (plotRect.bottom() - plotRect.top()) / 2;
    painter.setPen(QColor(100, 100, 100));
    painter.drawLine(plotRect.left(), zeroHeight, plotRect.right(), zeroHeight);
    // plot X and Y grid lines
    plotGridLines(&painter, plotRect);

    //Start painting graph
    PlotGraph(GraphBuffer, GraphTraceLen, plotRect, infoRect, &painter, 0);
    if (showDemod && DemodBufferLen > 8) {
        PlotDemod(DemodBuffer, DemodBufferLen, plotRect, infoRect, &painter, 2, g_DemodStartIdx);
    }
    if (g_useOverlays) {
        //init graph variables
        setMaxAndStart(s_Buff, GraphTraceLen, plotRect);
        PlotGraph(s_Buff, GraphTraceLen, plotRect, infoRect, &painter, 1);
    }
    // End graph drawing

    //Draw the cursors
    if (CursorAPos > GraphStart && xCoordOf(CursorAPos, plotRect) < plotRect.right()) {
        painter.setPen(QColor(255, 255, 0));
        painter.drawLine(xCoordOf(CursorAPos, plotRect), plotRect.top(), xCoordOf(CursorAPos, plotRect), plotRect.bottom());
    }
    if (CursorBPos > GraphStart && xCoordOf(CursorBPos, plotRect) < plotRect.right()) {
        painter.setPen(QColor(255, 0, 255));
        painter.drawLine(xCoordOf(CursorBPos, plotRect), plotRect.top(), xCoordOf(CursorBPos, plotRect), plotRect.bottom());
    }
    if (CursorCPos > GraphStart && xCoordOf(CursorCPos, plotRect) < plotRect.right()) {
        painter.setPen(QColor(255, 153, 0)); //orange
        painter.drawLine(xCoordOf(CursorCPos, plotRect), plotRect.top(), xCoordOf(CursorCPos, plotRect), plotRect.bottom());
    }
    if (CursorDPos > GraphStart && xCoordOf(CursorDPos, plotRect) < plotRect.right()) {
        painter.setPen(QColor(0, 0, 205)); //light blue
        painter.drawLine(xCoordOf(CursorDPos, plotRect), plotRect.top(), xCoordOf(CursorDPos, plotRect), plotRect.bottom());
    }

    //Draw annotations
    char str[200];
    sprintf(str, "@%d  dt=%d [%2.2f] zoom=%2.2f  CursorAPos=%d  CursorBPos=%d  GridX=%d  GridY=%d (%s) GridXoffset=%d",
            GraphStart,
            CursorBPos - CursorAPos,
            (CursorBPos - CursorAPos) / CursorScaleFactor,
            GraphPixelsPerPoint,
            CursorAPos,
            CursorBPos,
            PlotGridXdefault,
            PlotGridYdefault,
            GridLocked ? "Locked" : "Unlocked",
            GridOffset
           );
    painter.setPen(QColor(255, 255, 255));
    painter.drawText(20, infoRect.bottom() - 3, str);
}

Plot::Plot(QWidget *parent) : QWidget(parent), GraphStart(0), GraphPixelsPerPoint(1) {
    //Need to set this, otherwise we don't receive keypress events
    setFocusPolicy(Qt::StrongFocus);
    resize(400, 200);

    QPalette palette(QColor(0, 0, 0, 0));
    palette.setColor(QPalette::WindowText, QColor(255, 255, 255));
    palette.setColor(QPalette::Text, QColor(255, 255, 255));
    palette.setColor(QPalette::Button, QColor(100, 100, 100));
    setPalette(palette);
    setAutoFillBackground(true);
    CursorAPos = 0;
    CursorBPos = 0;

    setWindowTitle(tr("Sliders"));

    master = parent;
}

void Plot::closeEvent(QCloseEvent *event) {
    event->ignore();
    this->hide();
    g_useOverlays = false;
}

void Plot::mouseMoveEvent(QMouseEvent *event) {
    int x = event->x();
    x -= WIDTH_AXES;
    x = (int)(x / GraphPixelsPerPoint);
    x += GraphStart;
    if ((event->buttons() & Qt::LeftButton)) {
        CursorAPos = x;
    } else if (event->buttons() & Qt::RightButton) {
        CursorBPos = x;
    }
    this->update();
}

void Plot::keyPressEvent(QKeyEvent *event) {
    int offset;

    if (event->modifiers() & Qt::ShiftModifier) {
        if (PlotGridX)
            offset = PageWidth - (PageWidth % PlotGridX);
        else
            offset = PageWidth;
    } else {
        if (event->modifiers() & Qt::ControlModifier)
            offset = 1;
        else
            offset = (int)(20 / GraphPixelsPerPoint);
    }

    switch (event->key()) {
        case Qt::Key_Down:
            if (GraphPixelsPerPoint <= 50) {
                GraphPixelsPerPoint *= 2;
            }
            break;

        case Qt::Key_Up:
            if (GraphPixelsPerPoint >= 0.02) {
                GraphPixelsPerPoint /= 2;
            }
            break;

        case Qt::Key_Right:
            if (GraphPixelsPerPoint < 20) {
                GraphStart += offset;
            } else {
                GraphStart++;
            }
            break;

        case Qt::Key_Left:
            if (GraphPixelsPerPoint < 20) {
                GraphStart -= offset;
            } else {
                GraphStart--;
            }
            break;

        case Qt::Key_G:
            if (PlotGridX || PlotGridY) {
                PlotGridX = 0;
                PlotGridY = 0;
            } else {
                if (PlotGridXdefault < 0)
                    PlotGridXdefault = 64;
                if (PlotGridYdefault < 0)
                    PlotGridYdefault = 0;

                PlotGridX = PlotGridXdefault;
                PlotGridY = PlotGridYdefault;
            }
            break;

        case Qt::Key_H:

            puts("\n-----------------------------------------------------------------------");
            puts("PLOT window keystrokes");
            puts("\tKey                      Action");
            puts("-----------------------------------------------------------------------");
            puts("\tUP                       Zoom out");
            puts("\tDOWN                     Zoom in");
            puts("\tG                        Toggle grid display");
            puts("\tH                        Show help");
            puts("\tL                        Toggle lock grid relative to samples");
            puts("\tQ                        Hide window");
            puts("\tLEFT                     Move left");
            puts("\t<CTLR> LEFT              Move left 1 sample");
            puts("\t<SHIFT> LEFT             Page left");
            puts("\tLEFT MOUSE CLICK         Set yellow cursor");
            puts("\tRIGHT                    Move right");
            puts("\t<CTLR> RIGHT             Move right 1 sample");
            puts("\t<SHIFT> RIGHT            Page right");
            puts("\tRIGHT MOUSE CLICK        Set purple cursor");
            puts("-----------------------------------------------------------------------");
            break;

        case Qt::Key_L:
            GridLocked = !GridLocked;
            if (GridLocked)
                GridOffset += (GraphStart - unlockStart);
            else
                unlockStart = GraphStart;
            break;

        case Qt::Key_Q:
            master->hide();
            break;

        default:
            QWidget::keyPressEvent(event);
            return;
            break;
    }

    this->update();
}
