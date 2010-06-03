import sys
import types
import cherrypy
import urllib
import unittest
import re
import HTMLGenerator

class WebServer(object):
	def __init__(self):
		pass

	def index(self):
		worker = HTMLGenerator.Worker()
		return worker.Patches()
	index.exposed = True

	def PatchInfo(self,id = None):
		worker = HTMLGenerator.Worker()
		return worker.PatchInfo( id )
	PatchInfo.exposed = True

	def DownloadInfo(self,id = None):
		worker = HTMLGenerator.Worker()
		return worker.DownloadInfo( id )
	DownloadInfo.exposed = True

	def FileInfo(self,id = None):
		worker = HTMLGenerator.Worker()
		return worker.FileInfo( id )
	FileInfo.exposed = True

	def StartDiff( self, source_id, target_id ):
		worker = HTMLGenerator.Worker()
		return worker.StartDiff( source_id, target_id )
	StartDiff.exposed = True

	def ShowFunctionMatchInfo( self, source_id, target_id ):
		worker = HTMLGenerator.Worker()
		return worker.GetFunctionMatchInfo( source_id, target_id )
	ShowFunctionMatchInfo.exposed = True

	def ShowBasicBlockMatchInfo( self, source_id, target_id, source_address, target_address ):
		worker = HTMLGenerator.Worker()
		return worker.GetDisasmComparisonTextByFunctionAddress( source_id, target_id, source_address, target_address )
	ShowBasicBlockMatchInfo.exposed = True

if __name__ == '__main__':
	cherrypy.config.update({'server.socket_host': '0.0.0.0',
                        'server.socket_port': 80,
                       })
	cherrypy.quickstart( WebServer() )
