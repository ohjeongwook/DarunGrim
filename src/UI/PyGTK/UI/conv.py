import os
import re
import dircache

UIModules=[]
for filename in dircache.listdir("."):
	if filename[-3:]=='.ui':
		UIModules.append(filename[0:-3])

pyuic4_bat=''
for filename in [r'c:\python25\PyQt4\bin\pyuic4.bat',r'C:\Python25\Lib\site-packages\PyQt4\pyuic4.bat']:
	if os.path.exists(filename):
		pyuic4_bat=filename
		break

PrefixLines={}
for UIModule in UIModules:
	print "Converting "+UIModule+"..."
	if PrefixLines.has_key(UIModule):
		fd=open(UIModule+".py","w+")
		fd.write(PrefixLines[UIModule])
		fd.close()
		os.system(pyuic4_bat+" \""+UIModule+".ui\" >> \""+UIModule+".py\"")
	else:
		os.system(pyuic4_bat+" \""+UIModule+".ui\" > \""+UIModule+".py\"")
