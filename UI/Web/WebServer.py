import sys
import types
import cherrypy
import urllib
import unittest
import re
import HTMLGenerator
import os

class WebServer(object):
	def __init__(self):
		self.HTMLWorker = HTMLGenerator.Worker()

	def index(self):
		return self.HTMLWorker.Index()
	index.exposed = True

	def MSPatchList(self, operation = '' ):
		print 'MSPatchList'
		return self.HTMLWorker.MSPatchList( operation )
	MSPatchList.exposed = True

	def PatchInfo(self,id):
		return self.HTMLWorker.PatchInfo( id )
	PatchInfo.exposed = True

	def DownloadInfo(self, patch_id, id, operation = '' ):
		return self.HTMLWorker.DownloadInfo( patch_id, id, operation )
	DownloadInfo.exposed = True

	def FileInfo(self, patch_id, download_id, id):
		return self.HTMLWorker.FileInfo( patch_id, download_id, id )
	FileInfo.exposed = True

	def StartDiff( self, patch_id, download_id, file_id, source_id, target_id, show_detail = 0 ):
		return self.HTMLWorker.StartDiff( patch_id, download_id, file_id, source_id, target_id, show_detail )
	StartDiff.exposed = True

	def ShowFunctionMatchInfo( self, patch_id, download_id, file_id, source_id, target_id ):
		return self.HTMLWorker.GetFunctionMatchInfo( patch_id, download_id, file_id, source_id, target_id )
	ShowFunctionMatchInfo.exposed = True

	def ShowBasicBlockMatchInfo( self, patch_id, download_id, file_id, source_id, target_id, source_address, target_address ):
		return self.HTMLWorker.GetDisasmComparisonTextByFunctionAddress( patch_id, download_id, file_id, source_id, target_id, source_address, target_address )
	ShowBasicBlockMatchInfo.exposed = True

if __name__ == '__main__':
	cherrypy.config.update({'server.socket_host': '127.0.0.1',
                        'server.socket_port': 80,
                       })
	config = {
		'/data': {
			'tools.staticdir.on': True,
			'tools.staticdir.dir': os.path.join(os.getcwd(), 'data'),
			'tools.staticdir.content_types': {
				'js': 'application/javascript',
				'atom': 'application/atom+xml'
			}
		}
	}
	
	cherrypy.tree.mount( WebServer(), config=config )
	cherrypy.engine.start()
	cherrypy.engine.block()

	#cherrypy.quickstart( WebServer() )
