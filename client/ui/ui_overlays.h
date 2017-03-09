/********************************************************************************
** Form generated from reading UI file 'overlaystQ7020.ui'
**
** Created by: Qt User Interface Compiler version 4.8.6
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef OVERLAYSTQ7020_H
#define OVERLAYSTQ7020_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QFormLayout>
#include <QtGui/QHBoxLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QPushButton>
#include <QtGui/QSlider>
#include <QtGui/QSpacerItem>
#include <QtGui/QTabWidget>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_Form
{
public:
    QVBoxLayout *verticalLayout_3;
    QTabWidget *tabWidget_overlays;
    QWidget *tab;
    QVBoxLayout *verticalLayout_2;
    QFormLayout *formLayout;
    QLabel *label;
    QLabel *label_5;
    QSlider *horizontalSlider_window;
    QSpacerItem *verticalSpacer;
    QWidget *tab_3;
    QWidget *tab_2;
    QVBoxLayout *verticalLayout;
    QFormLayout *formLayout_2;
    QLabel *label_2;
    QLabel *label_6;
    QSlider *horizontalSlider_dirthr_up;
    QFormLayout *formLayout_3;
    QLabel *label_3;
    QLabel *label_7;
    QSlider *horizontalSlider_dirthr_down;
    QSpacerItem *verticalSpacer_2;
    QHBoxLayout *horizontalLayout;
    QPushButton *pushButton_apply;
    QPushButton *pushButton_sticky;
    QSpacerItem *horizontalSpacer;
    QLabel *label_4;

    void setupUi(QWidget *Form)
    {
        if (Form->objectName().isEmpty())
            Form->setObjectName(QString::fromUtf8("Form"));
        Form->resize(614, 286);
        verticalLayout_3 = new QVBoxLayout(Form);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        tabWidget_overlays = new QTabWidget(Form);
        tabWidget_overlays->setObjectName(QString::fromUtf8("tabWidget_overlays"));
        tab = new QWidget();
        tab->setObjectName(QString::fromUtf8("tab"));
        tab->setFocusPolicy(Qt::StrongFocus);
        verticalLayout_2 = new QVBoxLayout(tab);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        formLayout = new QFormLayout();
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        label = new QLabel(tab);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        label_5 = new QLabel(tab);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        formLayout->setWidget(0, QFormLayout::FieldRole, label_5);


        verticalLayout_2->addLayout(formLayout);

        horizontalSlider_window = new QSlider(tab);
        horizontalSlider_window->setObjectName(QString::fromUtf8("horizontalSlider_window"));
        horizontalSlider_window->setMinimum(10);
        horizontalSlider_window->setMaximum(10000);
        horizontalSlider_window->setValue(2000);
        horizontalSlider_window->setOrientation(Qt::Horizontal);

        verticalLayout_2->addWidget(horizontalSlider_window);

        verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_2->addItem(verticalSpacer);

        tabWidget_overlays->addTab(tab, QString());
        tab_3 = new QWidget();
        tab_3->setObjectName(QString::fromUtf8("tab_3"));
        tabWidget_overlays->addTab(tab_3, QString());
        tab_2 = new QWidget();
        tab_2->setObjectName(QString::fromUtf8("tab_2"));
        verticalLayout = new QVBoxLayout(tab_2);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        formLayout_2 = new QFormLayout();
        formLayout_2->setObjectName(QString::fromUtf8("formLayout_2"));
        label_2 = new QLabel(tab_2);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        formLayout_2->setWidget(0, QFormLayout::LabelRole, label_2);

        label_6 = new QLabel(tab_2);
        label_6->setObjectName(QString::fromUtf8("label_6"));

        formLayout_2->setWidget(0, QFormLayout::FieldRole, label_6);


        verticalLayout->addLayout(formLayout_2);

        horizontalSlider_dirthr_up = new QSlider(tab_2);
        horizontalSlider_dirthr_up->setObjectName(QString::fromUtf8("horizontalSlider_dirthr_up"));
        horizontalSlider_dirthr_up->setMaximum(128);
        horizontalSlider_dirthr_up->setValue(20);
        horizontalSlider_dirthr_up->setOrientation(Qt::Horizontal);

        verticalLayout->addWidget(horizontalSlider_dirthr_up);

        formLayout_3 = new QFormLayout();
        formLayout_3->setObjectName(QString::fromUtf8("formLayout_3"));
        label_3 = new QLabel(tab_2);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        formLayout_3->setWidget(0, QFormLayout::LabelRole, label_3);

        label_7 = new QLabel(tab_2);
        label_7->setObjectName(QString::fromUtf8("label_7"));

        formLayout_3->setWidget(0, QFormLayout::FieldRole, label_7);


        verticalLayout->addLayout(formLayout_3);

        horizontalSlider_dirthr_down = new QSlider(tab_2);
        horizontalSlider_dirthr_down->setObjectName(QString::fromUtf8("horizontalSlider_dirthr_down"));
        horizontalSlider_dirthr_down->setMaximum(127);
        horizontalSlider_dirthr_down->setOrientation(Qt::Horizontal);

        verticalLayout->addWidget(horizontalSlider_dirthr_down);

        verticalSpacer_2 = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer_2);

        tabWidget_overlays->addTab(tab_2, QString());

        verticalLayout_3->addWidget(tabWidget_overlays);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        pushButton_apply = new QPushButton(Form);
        pushButton_apply->setObjectName(QString::fromUtf8("pushButton_apply"));

        horizontalLayout->addWidget(pushButton_apply);

        pushButton_sticky = new QPushButton(Form);
        pushButton_sticky->setObjectName(QString::fromUtf8("pushButton_sticky"));

        horizontalLayout->addWidget(pushButton_sticky);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        label_4 = new QLabel(Form);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        horizontalLayout->addWidget(label_4);


        verticalLayout_3->addLayout(horizontalLayout);


        retranslateUi(Form);
        QObject::connect(horizontalSlider_window, SIGNAL(valueChanged(int)), label_4, SLOT(setNum(int)));
        QObject::connect(horizontalSlider_window, SIGNAL(valueChanged(int)), label_5, SLOT(setNum(int)));
        QObject::connect(horizontalSlider_dirthr_up, SIGNAL(valueChanged(int)), label_6, SLOT(setNum(int)));
        QObject::connect(horizontalSlider_dirthr_down, SIGNAL(valueChanged(int)), label_7, SLOT(setNum(int)));

        tabWidget_overlays->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(Form);
    } // setupUi

    void retranslateUi(QWidget *Form)
    {
        Form->setWindowTitle(QApplication::translate("Form", "Overlays", 0, QApplication::UnicodeUTF8));
        label->setText(QApplication::translate("Form", "Window size", 0, QApplication::UnicodeUTF8));
        label_5->setText(QString());
        tabWidget_overlays->setTabText(tabWidget_overlays->indexOf(tab), QApplication::translate("Form", "Autocorrelate", 0, QApplication::UnicodeUTF8));
        tabWidget_overlays->setTabText(tabWidget_overlays->indexOf(tab_3), QApplication::translate("Form", "Askdemod", 0, QApplication::UnicodeUTF8));
        label_2->setText(QApplication::translate("Form", "Up", 0, QApplication::UnicodeUTF8));
        label_6->setText(QString());
        label_3->setText(QApplication::translate("Form", "Down", 0, QApplication::UnicodeUTF8));
        label_7->setText(QString());
        tabWidget_overlays->setTabText(tabWidget_overlays->indexOf(tab_2), QApplication::translate("Form", "Dirthreshold", 0, QApplication::UnicodeUTF8));
        pushButton_apply->setText(QApplication::translate("Form", "Apply", 0, QApplication::UnicodeUTF8));
        pushButton_sticky->setText(QApplication::translate("Form", "Sticky", 0, QApplication::UnicodeUTF8));
        label_4->setText(QApplication::translate("Form", "TextLabel", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class Form: public Ui_Form {};
} // namespace Ui

QT_END_NAMESPACE

#endif // OVERLAYSTQ7020_H
