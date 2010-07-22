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
		pass

	def index(self):
		html_worker = HTMLGenerator.Worker()
		return html_worker.Index()
	index.exposed = True

	def FileList(self, company_name = None, filename = None, version_string = None ):
		html_worker = HTMLGenerator.Worker()	
		return html_worker.FileList( company_name , filename , version_string )
	FileList.exposed = True

	def FileTree(self, company_name = None, filename = None, version_string = None ):
		html_worker = HTMLGenerator.Worker()	
		return html_worker.FileTree( company_name , filename , version_string )
	FileTree.exposed = True

	def FileTreeJSON(self, company_name = None, filename = None, version_string = None ):
		html_worker = HTMLGenerator.Worker()	
		return html_worker.FileTreeJSON( company_name , filename , version_string )
	FileTreeJSON.exposed = True

	def FileImport( self, folder = None ):
		html_worker = HTMLGenerator.Worker()	
		return html_worker.FileImport( folder )
	FileImport.exposed = True

	def MSPatchList(self, operation = '' ):
		print 'MSPatchList'
		html_worker = HTMLGenerator.Worker()
		return html_worker.MSPatchList( operation )
	MSPatchList.exposed = True

	def PatchInfo(self,id):
		html_worker = HTMLGenerator.Worker()
		return html_worker.PatchInfo( id )
	PatchInfo.exposed = True

	def DownloadInfo(self, patch_id, id, operation = '' ):
		html_worker = HTMLGenerator.Worker()
		return html_worker.DownloadInfo( patch_id, id, operation )
	DownloadInfo.exposed = True

	def FileInfo(self, patch_id, download_id, id):
		html_worker = HTMLGenerator.Worker()
		return html_worker.FileInfo( patch_id, download_id, id )
	FileInfo.exposed = True

	def StartDiff( self, source_id, target_id, patch_id = 0, download_id = 0, file_id = 0, show_detail = 0 ):
		html_worker = HTMLGenerator.Worker()
		return html_worker.StartDiff( patch_id, download_id, file_id, source_id, target_id, show_detail )
	StartDiff.exposed = True

	def ShowFunctionMatchInfo( self, patch_id, download_id, file_id, source_id, target_id ):
		html_worker = HTMLGenerator.Worker()
		return html_worker.GetFunctionMatchInfo( patch_id, download_id, file_id, source_id, target_id )
	ShowFunctionMatchInfo.exposed = True

	def ShowBasicBlockMatchInfo( self, patch_id, download_id, file_id, source_id, target_id, source_address, target_address ):
		html_worker = HTMLGenerator.Worker()
		return html_worker.GetDisasmComparisonTextByFunctionAddress( patch_id, download_id, file_id, source_id, target_id, source_address, target_address )
	ShowBasicBlockMatchInfo.exposed = True

	def SyncIDA( self, source_id, target_id ):
		html_worker = HTMLGenerator.Worker()
		return html_worker.SyncIDA( source_id, target_id )
	SyncIDA.exposed = True

if __name__ == '__main__':
	import ConfigParser
	import io

	config_file = 'DarunGrim3.cfg'
	fd = open( config_file )
	config_data = fd.read()
	fd.close()
	config = ConfigParser.RawConfigParser()
	config.readfp(io.BytesIO( config_data ))
					
	port = int( config.get("Global", "Port") )

	cherrypy.config.update({'server.socket_host': '127.0.0.1',
                        'server.socket_port': port,
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

