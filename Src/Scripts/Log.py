from PySide.QtCore import *
from PySide.QtGui import *
from PySide.QtSql import *
import pprint
import multiprocessing.forking
import multiprocessing
from multiprocessing import Process
import time
import os
import operator
import subprocess
import sys

class LogTextBoxDialog(QDialog):
	def __init__(self,parent=None):
		super(LogTextBoxDialog,self).__init__(parent)
		self.setWindowTitle("Log")
		self.setWindowIcon(QIcon('DarunGrim.png'))

		self.text=QTextEdit()
		self.text.setReadOnly(True)
		vlayout=QVBoxLayout()
		vlayout.addWidget(self.text)

		self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
		self.buttonBox.accepted.connect(self.accept)
		self.buttonBox.rejected.connect(self.Cancel)
		vlayout.addWidget(self.buttonBox)

		self.setLayout(vlayout)
		self.setWindowFlags(self.windowFlags()|Qt.WindowSystemMenuHint|Qt.WindowMinMaxButtonsHint)
		self.textLen=0
		self.CancelCallback=None

	def DisableClose(self):
		self.setWindowFlags(Qt.CustomizeWindowHint|Qt.WindowMinMaxButtonsHint)
		self.buttonBox.button(QDialogButtonBox.Ok).setEnabled(False)

	def EnableClose(self):
		self.buttonBox.button(QDialogButtonBox.Ok).setEnabled(True)

	def SetCancelCallback(self,callback):
		self.CancelCallback=callback

	def Cancel(self):
		if self.CancelCallback!=None:
			self.CancelCallback()

	def addText(self,text):
		if self.textLen> 1024*1024:
			self.text.clear()
			self.textLen=0
		self.text.moveCursor(QTextCursor.End)
		self.text.insertPlainText(text)
		self.text.moveCursor(QTextCursor.End)
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

class PrintHook:
	def __init__(self,out=True,func=None,arg=None):
		self.func=func
		self.OrigOut=None
		self.Out=out
		self.Arg=arg

	def Start(self):
		if self.Out==True:
			sys.stdout=self
			self.OrigOut=sys.__stdout__
		else:
			sys.stderr=self
			self.OrigOut=sys.__stderr__
	
	def Stop(self):
		self.OrigOut.flush()
		if self.Out:
			sys.stdout=sys.__stdout__
		else:
			sys.stderr=sys.__stderr__

	def write(self,text):
		if self.Arg!=None:
			self.func(text,self.Arg)
		else:
			self.func(text)

	def flush(self):
		pass

	def __getattr__(self,name):
		try:
			return self.OrigOut.__getattr__(name)
		except:
			pass

if __name__=='__main__':
	phOut=PrintHook()
	phOut.Start()

	phErr=PrintHook(0)
	phErr.Start()

	print "Hello"
