import sys
sys.path.append('..')
import PatchDatabaseWrapper
import PatchTimeline
from mako.template import Template

PatchesTemplateText = """<%def name="layoutdata(somedata)">
	<table>
	% for item in somedata:
		<tr>
			<td><a href="PatchInfo?id=${item.id}">${item.name}</a></td>
			<td>${item.title}</td>
		</tr>
	% endfor
	</table>
</%def>
<html>
<body>
<%self:layoutdata somedata="${patches}" args="col">\
Body data: ${col}\
</%self:layoutdata>
</body>
</html>"""

PatchInfoTemplateText = """<%def name="layoutdata(somedata)">
	<table>
	% for item in somedata:
		<tr>
			<td><a href="DownloadInfo?id=${item.id}">${item.label}</a></td>
			<td>${item.filename}</td>
		</tr>
	% endfor
	</table>
</%def>
<html>
<body>
<%self:layoutdata somedata="${downloads}" args="col">\
Body data: ${col}\
</%self:layoutdata>
</body>
</html>"""

DownloadInfoTemplateText = """<%def name="layoutdata(somedata)">
	<table>
	% for item in somedata:
		<tr>
			<td><a href="FileInfo?id=${item.id}">${item.filename}</a></td>
			<td>${item.version_string}</td>
		</tr>
	% endfor
	</table>
</%def>
<html>
<body>
<%self:layoutdata somedata="${files}" args="col">\
Body data: ${col}\
</%self:layoutdata>
</body>
</html>"""


class Worker:
	def __init__ ( self, database = r'..\test.db' ):
		self.DatabaseName = database
		self.Database = PatchDatabaseWrapper.Database( self.DatabaseName )

	def Patches( self ):
		mytemplate = Template( PatchesTemplateText )
		patches = self.Database.GetPatches()
		return mytemplate.render( patches=patches )

	def PatchInfo( self, id ):
		mytemplate = Template( PatchInfoTemplateText )
		downloads = self.Database.GetDownloadByPatchID( id )
		return mytemplate.render( downloads=downloads )

	def DownloadInfo( self, id ):
		mytemplate = Template( DownloadInfoTemplateText )
		files = self.Database.GetFileByDownloadID( id )
		return mytemplate.render( files=files )

	def FileInfo( self, id ):
		mytemplate = Template( DownloadInfoTemplateText )
		files = self.Database.GetFileByDownloadID( id )
		return mytemplate.render( files=files )

if __name__ == '__main__':
	worker = Worker()
	print worker.Patches()
