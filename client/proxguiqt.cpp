//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// GUI (QT)
//-----------------------------------------------------------------------------

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
#include "proxguiqt.h"
#include "proxgui.h"

int GridOffset= 0;
bool GridLocked= 0;
int startMax;
int PageWidth;

void ProxGuiQT::ShowGraphWindow(void)
{
	emit ShowGraphWindowSignal();
}

void ProxGuiQT::RepaintGraphWindow(void)
{
	emit RepaintGraphWindowSignal();
}

void ProxGuiQT::HideGraphWindow(void)
{
	emit HideGraphWindowSignal();
}

void ProxGuiQT::_ShowGraphWindow(void)
{
	if(!plotapp)
		return;

	if (!plotwidget)
		plotwidget = new ProxWidget();

	plotwidget->show();
}

void ProxGuiQT::_RepaintGraphWindow(void)
{
	if (!plotapp || !plotwidget)
		return;

	plotwidget->update();
}

void ProxGuiQT::_HideGraphWindow(void)
{
	if (!plotapp || !plotwidget)
		return;

	plotwidget->hide();
}

void ProxGuiQT::MainLoop()
{
	plotapp = new QApplication(argc, argv);

	connect(this, SIGNAL(ShowGraphWindowSignal()), this, SLOT(_ShowGraphWindow()));
	connect(this, SIGNAL(RepaintGraphWindowSignal()), this, SLOT(_RepaintGraphWindow()));
	connect(this, SIGNAL(HideGraphWindowSignal()), this, SLOT(_HideGraphWindow()));

	plotapp->exec();
}

ProxGuiQT::ProxGuiQT(int argc, char **argv) : plotapp(NULL), plotwidget(NULL), argc(argc), argv(argv) {}

ProxGuiQT::~ProxGuiQT(void)
{
	if (plotwidget) {
		delete plotwidget;
		plotwidget = NULL;
	}

	if (plotapp) {
		plotapp->quit();
		delete plotapp;
		plotapp = NULL;
	}
}

void ProxWidget::paintEvent(QPaintEvent *event)
{
	QPainter painter(this);
	QPainterPath penPath, whitePath, greyPath, lightgreyPath, cursorAPath, cursorBPath;
	QRect r;
	QBrush brush(QColor(100, 255, 100));
	QPen pen(QColor(100, 255, 100));

	painter.setFont(QFont("Arial", 10));

	if(GraphStart < 0)
		GraphStart = 0;

	if (CursorAPos > GraphTraceLen)
		CursorAPos= 0;

	if(CursorBPos > GraphTraceLen)
		CursorBPos= 0;

	r = rect();

	painter.fillRect(r, QColor(0, 0, 0));

	whitePath.moveTo(r.left() + 40, r.top());
	whitePath.lineTo(r.left() + 40, r.bottom());

	int zeroHeight = r.top() + (r.bottom() - r.top()) / 2;

	greyPath.moveTo(r.left(), zeroHeight);
	greyPath.lineTo(r.right(), zeroHeight);
	painter.setPen(QColor(100, 100, 100));
	painter.drawPath(greyPath);

	PageWidth= (int)((r.right() - r.left() - 40) / GraphPixelsPerPoint);
	
        // plot X and Y grid lines
        int i;
        if ((PlotGridX > 0) && ((PlotGridX * GraphPixelsPerPoint) > 1)) {
        	for(i = 40 + (GridOffset * GraphPixelsPerPoint); i < r.right(); i += (int)(PlotGridX * GraphPixelsPerPoint)) {
        		//SelectObject(hdc, GreyPenLite);
        		//MoveToEx(hdc, r.left + i, r.top, NULL);
        		//LineTo(hdc, r.left + i, r.bottom);
        		lightgreyPath.moveTo(r.left()+i,r.top());
				lightgreyPath.lineTo(r.left()+i,r.bottom());
				painter.drawPath(lightgreyPath);
        	} 
        } 
        if ((PlotGridY > 0) && ((PlotGridY * GraphPixelsPerPoint) > 1)){
        	for(i = 0; i < ((r.top() + r.bottom())>>1); i += (int)(PlotGridY * GraphPixelsPerPoint)) {
       			lightgreyPath.moveTo(r.left() + 40,zeroHeight + i);
				lightgreyPath.lineTo(r.right(),zeroHeight + i);
				painter.drawPath(lightgreyPath);
        		lightgreyPath.moveTo(r.left() + 40,zeroHeight - i);
				lightgreyPath.lineTo(r.right(),zeroHeight - i);
				painter.drawPath(lightgreyPath);
        	}
        }

	startMax = (GraphTraceLen - (int)((r.right() - r.left() - 40) / GraphPixelsPerPoint));
	
	if(startMax < 0) 
		startMax = 0;
	
	if(GraphStart > startMax) 
		GraphStart = startMax;

	int absYMax = 1;

	for(i = GraphStart; ; i++) {

		if(i >= GraphTraceLen) break;
		
		if(fabs((double)GraphBuffer[i]) > absYMax)
			absYMax = (int)fabs((double)GraphBuffer[i]);
		
		int x = 40 + (int)((i - GraphStart)*GraphPixelsPerPoint);

		if(x > r.right()) break;
	}

	absYMax = (int)(absYMax*1.2 + 1);
	
	// number of points that will be plotted
	int span = (int)((r.right() - r.left()) / GraphPixelsPerPoint);
	
	// one label every 100 pixels, let us say
	int labels = (r.right() - r.left() - 40) / 100;
	if(labels <= 0) labels = 1;
	
	int pointsPerLabel = span / labels;
	if(pointsPerLabel <= 0) pointsPerLabel = 1;

	int yMin = INT_MAX;
	int yMax = INT_MIN;
	int yMean = 0;
	int n = 0;

	for(i = GraphStart; ; i++) {
		if(i >= GraphTraceLen) break;

		int x = 40 + (int)((i - GraphStart)*GraphPixelsPerPoint);
		if(x > r.right() + GraphPixelsPerPoint) break;

		int y = GraphBuffer[i];
		if(y < yMin)
			yMin = y;

		if(y > yMax)
			yMax = y;

		yMean += y;
		n++;

		y = (y * (r.top() - r.bottom()) / (2*absYMax)) + zeroHeight;
		
		if(i == GraphStart)
			penPath.moveTo(x, y);
		else
			penPath.lineTo(x, y);
		

		if(GraphPixelsPerPoint > 10) {
			QRect f(QPoint(x - 3, y - 3),QPoint(x + 3, y + 3));
			painter.fillRect(f, brush);
		}

		if(((i - GraphStart) % pointsPerLabel == 0) && i != GraphStart) {
			whitePath.moveTo(x, zeroHeight - 3);
			whitePath.lineTo(x, zeroHeight + 3);

			char str[100];
			sprintf(str, "+%d", (i - GraphStart));

			painter.setPen(QColor(255, 255, 255));
			QRect size;
			QFontMetrics metrics(painter.font());
			size = metrics.boundingRect(str);
			painter.drawText(x - (size.right() - size.left()), zeroHeight + 9, str);

			penPath.moveTo(x,y);
		}

		if(i == CursorAPos || i == CursorBPos) {
			QPainterPath *cursorPath;

			if(i == CursorAPos)
				cursorPath = &cursorAPath;
			else
				cursorPath = &cursorBPath;
			
			cursorPath->moveTo(x, r.top());
			cursorPath->lineTo(x, r.bottom());
			penPath.moveTo(x, y);
		}
	}

	if(n != 0)
		yMean /= n;

	painter.setPen(QColor(255, 255, 255));
	painter.drawPath(whitePath);
	painter.setPen(pen);
	painter.drawPath(penPath);
	painter.setPen(QColor(255, 255, 0));
	painter.drawPath(cursorAPath);
	painter.setPen(QColor(255, 0, 255));
	painter.drawPath(cursorBPath);

	char str[200];
	sprintf(str, "@%d   max=%d min=%d mean=%d n=%d/%d    dt=%d [%.3f] zoom=%.3f CursorA=%d [%d] CursorB=%d [%d]    GridX=%d GridY=%d (%s)",
			GraphStart, yMax, yMin, yMean, n, GraphTraceLen,
			CursorBPos - CursorAPos,
			(CursorBPos - CursorAPos)/CursorScaleFactor,
			GraphPixelsPerPoint,
			CursorAPos,
			GraphBuffer[CursorAPos],
			CursorBPos,
			GraphBuffer[CursorBPos],
			PlotGridXdefault,
			PlotGridYdefault,
			GridLocked ? "Locked" : "Unlocked"
		);

	painter.setPen(QColor(255, 255, 255));
	painter.drawText(50, r.bottom() - 20, str);
}

ProxWidget::ProxWidget(QWidget *parent) : QWidget(parent), GraphStart(0), GraphPixelsPerPoint(1)
{
	resize(600, 300);

	QPalette palette(QColor(0,0,0,0));
	palette.setColor(QPalette::WindowText, QColor(255,255,255));
	palette.setColor(QPalette::Text, QColor(255,255,255));
	palette.setColor(QPalette::Button, QColor(100, 100, 100));
	setPalette(palette);
	setAutoFillBackground(true);
	CursorAPos = 0;
	CursorBPos = 0;
}

void ProxWidget::closeEvent(QCloseEvent *event)
{
	event->ignore();
	this->hide();
}

void ProxWidget::mouseMoveEvent(QMouseEvent *event)
{
	int x = event->x();
	x -= 40;
	x = (int)(x / GraphPixelsPerPoint);
	x += GraphStart;
	if((event->buttons() & Qt::LeftButton)) {
		CursorAPos = x;
	} else if (event->buttons() & Qt::RightButton) {
		CursorBPos = x;
	}

	this->update();
}

void ProxWidget::keyPressEvent(QKeyEvent *event)
{
	int	offset;
	int	gridchanged;

	gridchanged= 0;

	if(event->modifiers() & Qt::ShiftModifier) {
		if (PlotGridX)
			offset= PageWidth - (PageWidth % PlotGridX);
		else
			offset= PageWidth;
	} else 
		if(event->modifiers() & Qt::ControlModifier)
			offset= 1;
		else
			offset= (int)(20 / GraphPixelsPerPoint);

	switch(event->key()) {
		case Qt::Key_Down:
			if(GraphPixelsPerPoint <= 50) {
				GraphPixelsPerPoint *= 2;
			}
			break;

		case Qt::Key_Up:
			if(GraphPixelsPerPoint >= 0.02) {
				GraphPixelsPerPoint /= 2;
			}
			break;

		case Qt::Key_Right:
			if(GraphPixelsPerPoint < 20) {
				if (PlotGridX && GridLocked && GraphStart < startMax){
					GridOffset -= offset;
					GridOffset %= PlotGridX;
					gridchanged= 1;
				}
				GraphStart += offset;
			} else {
				if (PlotGridX && GridLocked && GraphStart < startMax){
					GridOffset--;
					GridOffset %= PlotGridX;
					gridchanged= 1;
				}
				GraphStart++;
			}
			if(GridOffset < 0) {
				GridOffset += PlotGridX;
			}
			if (gridchanged)
				if (GraphStart > startMax) {
					GridOffset += (GraphStart - startMax);
					GridOffset %= PlotGridX;
				}
			break;

		case Qt::Key_Left:
			if(GraphPixelsPerPoint < 20) {
				if (PlotGridX && GridLocked && GraphStart > 0){
					GridOffset += offset;
					GridOffset %= PlotGridX;
					gridchanged= 1;
				}
				GraphStart -= offset;
			} else {
				if (PlotGridX && GridLocked && GraphStart > 0){
					GridOffset++;
					GridOffset %= PlotGridX;
					gridchanged= 1;
				}
				GraphStart--;
			}
			if (gridchanged){
				if (GraphStart < 0)
					GridOffset += GraphStart;
				if(GridOffset < 0)
					GridOffset += PlotGridX;
			GridOffset %= PlotGridX;
			}
			break;

		case Qt::Key_G:
			if(PlotGridX || PlotGridY) {
				PlotGridX= 0;
				PlotGridY= 0;
			} else {
				PlotGridX= PlotGridXdefault;
				PlotGridY= PlotGridYdefault;
				}
			break;

		case Qt::Key_H:
			puts("Plot Window Keystrokes:\n");
			puts(" Key                      Action\n");
			puts(" DOWN                     Zoom in");
			puts(" G                        Toggle grid display");
			puts(" H                        Show help");
			puts(" L                        Toggle lock grid relative to samples");
			puts(" LEFT                     Move left");
			puts(" <CTL>LEFT                Move left 1 sample");
			puts(" <SHIFT>LEFT              Page left");
			puts(" LEFT-MOUSE-CLICK         Set yellow cursor");
			puts(" Q                        Hide window");
			puts(" RIGHT                    Move right");
			puts(" <CTL>RIGHT               Move right 1 sample");
			puts(" <SHIFT>RIGHT             Page right");
			puts(" RIGHT-MOUSE-CLICK        Set purple cursor");
			puts(" UP                       Zoom out");
			puts("");
			puts("Use client window 'data help' for more plot commands\n");
			break;

		case Qt::Key_L:
			GridLocked= !GridLocked;
			break;

		case Qt::Key_Q:
			this->hide();
			break;

		default:
			QWidget::keyPressEvent(event);
			return;
			break;
	}

	this->update();
}
