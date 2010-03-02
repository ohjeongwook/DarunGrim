# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'UI_BinaryDifferMain.ui'
#
# Created: Fri Sep 12 21:21:29 2008
#      by: PyQt4 UI code generator 4.4.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1187, 723)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setGeometry(QtCore.QRect(0, 25, 1187, 675))
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtGui.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.splitter_2 = QtGui.QSplitter(self.centralwidget)
        self.splitter_2.setOrientation(QtCore.Qt.Vertical)
        self.splitter_2.setObjectName("splitter_2")
        self.splitter = QtGui.QSplitter(self.splitter_2)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName("splitter")
        self.graphicsView_Before = QtGui.QGraphicsView(self.splitter)
        self.graphicsView_Before.setObjectName("graphicsView_Before")
        self.graphicsView_After = QtGui.QGraphicsView(self.splitter)
        self.graphicsView_After.setObjectName("graphicsView_After")
        self.treeWidget_Matches = QtGui.QTreeWidget(self.splitter_2)
        self.treeWidget_Matches.setObjectName("treeWidget_Matches")
        self.gridLayout.addWidget(self.splitter_2, 0, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1187, 25))
        self.menubar.setObjectName("menubar")
        self.menu_File = QtGui.QMenu(self.menubar)
        self.menu_File.setObjectName("menu_File")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setGeometry(QtCore.QRect(0, 700, 1187, 23))
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionOpen_IDB_For_UnPatched_Binary = QtGui.QAction(MainWindow)
        self.actionOpen_IDB_For_UnPatched_Binary.setObjectName("actionOpen_IDB_For_UnPatched_Binary")
        self.actionOpen_IDB_For_Patched_Binary = QtGui.QAction(MainWindow)
        self.actionOpen_IDB_For_Patched_Binary.setObjectName("actionOpen_IDB_For_Patched_Binary")
        self.actionStart_Diffing = QtGui.QAction(MainWindow)
        self.actionStart_Diffing.setObjectName("actionStart_Diffing")
        self.menu_File.addAction(self.actionOpen_IDB_For_UnPatched_Binary)
        self.menu_File.addAction(self.actionOpen_IDB_For_Patched_Binary)
        self.menu_File.addAction(self.actionStart_Diffing)
        self.menubar.addAction(self.menu_File.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QtGui.QApplication.translate("MainWindow", "MainWindow", None, QtGui.QApplication.UnicodeUTF8))
        self.treeWidget_Matches.headerItem().setText(0, QtGui.QApplication.translate("MainWindow", "Before", None, QtGui.QApplication.UnicodeUTF8))
        self.treeWidget_Matches.headerItem().setText(1, QtGui.QApplication.translate("MainWindow", "After", None, QtGui.QApplication.UnicodeUTF8))
        self.menu_File.setTitle(QtGui.QApplication.translate("MainWindow", "&File", None, QtGui.QApplication.UnicodeUTF8))
        self.actionOpen_IDB_For_UnPatched_Binary.setText(QtGui.QApplication.translate("MainWindow", "Open &IDB For Unpatched Binary", None, QtGui.QApplication.UnicodeUTF8))
        self.actionOpen_IDB_For_Patched_Binary.setText(QtGui.QApplication.translate("MainWindow", "Open &IDB ForPatched Binary", None, QtGui.QApplication.UnicodeUTF8))
        self.actionStart_Diffing.setText(QtGui.QApplication.translate("MainWindow", "Start Dfifing", None, QtGui.QApplication.UnicodeUTF8))

