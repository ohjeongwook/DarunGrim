from PySide.QtCore import *
from PySide.QtGui import *
from PySide.QtSql import *
import DarunGrimDatabase
import DiffEngine
from Graphs import *
import FlowGrapher
import FileStoreBrowser
import FileStoreDatabase
import DarunGrimEngine

import pprint
import multiprocessing.forking
import multiprocessing
from multiprocessing import Process
import time
import os
import operator
import subprocess

class LogTextBoxDialog(QDialog):
	def __init__(self,parent=None):
		super(LogTextBoxDialog,self).__init__(parent)
		self.setWindowTitle("Log")

		self.text=QTextEdit()
		self.text.setReadOnly(True)
		vlayout=QVBoxLayout()
		vlayout.addWidget(self.text)

		buttonBox = QDialogButtonBox(QDialogButtonBox.Close)
		buttonBox.rejected.connect(self.reject)
		vlayout.addWidget(buttonBox)

		self.setLayout(vlayout)
		self.setWindowFlags(self.windowFlags()|Qt.WindowSystemMenuHint|Qt.WindowMinMaxButtonsHint)
		self.textLen=0

	def addText(self,text):
		if self.textLen> 1024*1024:
			self.text.clear()
			self.textLen=0
		self.text.append(text)
		self.textLen+=len(text)

	def keyPressEvent(self,e):
		key=e.key()

		if key==Qt.Key_Return or key==Qt.Key_Enter:
			return
		else:
			super(LogTextBoxDialog,self).keyPressEvent(e)


class LogThread(QThread):
	data_read=Signal(object)

	def __init__(self,filename):
		QThread.__init__(self)
		self.filename=filename
		self.endLoop=False

	def run(self):
		fd=None
		while not self.endLoop:
			try:
				fd=open(self.filename,'rb')
				break
			except:
				pass

		if fd!=None:
			while not self.endLoop:
				data=fd.read()
				if data:
					self.data_read.emit(data)

			fd.close()

	def end(self):
		self.endLoop=True

class QueReadThread(QThread):
	data_read=Signal(object)

	def __init__(self,q):
		QThread.__init__(self)
		self.q=q

	def run(self):
		while 1:
			data=self.q.get()
			if data:
				self.data_read.emit(data)

	def end(self):
		pass