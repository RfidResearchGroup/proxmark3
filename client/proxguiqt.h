//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// GUI (QT)
//-----------------------------------------------------------------------------

#include <QApplication>
#include <QPushButton>
#include <QObject>
#include <QWidget>
#include <QPainter>

class ProxWidget : public QWidget
{
	Q_OBJECT;

	private:
		int GraphStart;
		double GraphPixelsPerPoint;
		int CursorAPos;
		int CursorBPos;

	public:
		ProxWidget(QWidget *parent = 0);

	protected:
		void paintEvent(QPaintEvent *event);
		void closeEvent(QCloseEvent *event);
		void mouseMoveEvent(QMouseEvent *event);
		void mousePressEvent(QMouseEvent *event) { mouseMoveEvent(event); }
		void keyPressEvent(QKeyEvent *event);
};

class ProxGuiQT : public QObject
{
	Q_OBJECT;

	private:
		QApplication *plotapp;
		ProxWidget *plotwidget;
		int argc;
		char **argv;
		void (*main_func)(void);
	
	public:
		ProxGuiQT(int argc, char **argv);
		~ProxGuiQT(void);
		void ShowGraphWindow(void);
		void RepaintGraphWindow(void);
		void HideGraphWindow(void);
		void MainLoop(void);
	
	private slots:
		void _ShowGraphWindow(void);
		void _RepaintGraphWindow(void);
		void _HideGraphWindow(void);

	signals:
		void ShowGraphWindowSignal(void);
		void RepaintGraphWindowSignal(void);
		void HideGraphWindowSignal(void);
};
