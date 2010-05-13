import sqlalchemy
from sqlalchemy import Table, Column, Integer, String, Binary, MetaData, ForeignKey
from sqlalchemy.orm import mapper, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, backref

Base = declarative_base()

class Patch(Base):
	__tablename__ = 'patches'
	
	id = Column( Integer, primary_key = True )
	name = Column( String )
	title = Column( String )
	url = Column( String )
	html_data = Column( Binary ) 

	def __init__( self, name, title, url, html_data ):
		self.name = name
		self.title = title
		self.url = url
		self.html_data = html_data
		
	def __repr__( self ):
		return "<Patches('%s','%s','%s')>" % ( self.name, self.title, self.url )

class CVE(Base):
	__tablename__ = 'cves'
	id = Column( Integer, primary_key = True )
	cve_string = Column( String )	
	name = Column( String )	

	patch_id = Column( Integer, ForeignKey('patches.id'))
	patches = relationship(Patch, backref=backref('cves', order_by=id))

	def __init__( self, cve_string, name ):
		self.cve_string = cve_string
		self.name = name
		
	def __repr__( self ):
		return "<CVEs('%s','%s')>" % ( self.cve_string, self.name )

class Download(Base):
	__tablename__ = 'downloads'
	id = Column( Integer, primary_key = True )
	operating_system = Column( String )
	label = Column( String )	
	url = Column( String )
	filename = Column( String )
	maximum_security_impact = Column( String )
	aggregate_severity_rating = Column( String )
	bulletins_replaced = Column( String )

	patch_id = Column( Integer, ForeignKey('patches.id'))
	patches = relationship(Patch, backref=backref('downloads', order_by=id))

	def __init__( self, operating_system, label, url, filename, maximum_security_impact, aggregate_severity_rating, bulletins_replaced ):
		self.operating_system = operating_system
		self.label = label
		self.url = url
		self.filename = filename
		self.maximum_security_impact = maximum_security_impact
		self.aggregate_severity_rating = aggregate_severity_rating
		self.bulletins_replaced = bulletins_replaced
		
	def __repr__( self ):
		return "<Downloads('%s','%s','%s')>" % ( self.label, self.url, self.filename )
 
class FileIndex(Base):
	__tablename__ = 'fileindexes'
	
	id = Column( Integer, primary_key = True )
	operating_system = Column( String )
	service_pack = Column( String )
	filename = Column( String )
	company_name = Column( String )
	version_string = Column( String )
	patch_identifier = Column( String ) #ex) MS09-011
	version_number = Column( String )
	release_plan = Column( String )
	full_path = Column( String )

	download_id = Column( Integer, ForeignKey('downloads.id'))
	downloads = relationship(Download, backref=backref('fileindexes', order_by=id))

	def __init__( self, operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path ):
		self.operating_system = operating_system
		self.service_pack = service_pack
		self.filename = filename
		self.company_name = company_name
		self.version_string = version_string
		self.patch_identifier = patch_identifier
		#TODO: Parser version_string
		#self.version_number = 
		#self.release_plan = 
		self.full_path = full_path

	def __repr__( self ):
		return "<FileIndex('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )>" % ( self.operating_system, self.service_pack, self.filename, self.company_name, self.version_string, self.patch_identifier, self.version_number, self.release_plan, self.full_path )

class Database:
	DebugLevel = 2
	def __init__( self, filename ):
		echo = False
		if self.DebugLevel > 2:
			echo = True
		self.Engine = sqlalchemy.create_engine( 'sqlite:///' + filename, echo = echo )

		metadata = Base.metadata
		metadata.create_all( self.Engine )

		self.Session = sessionmaker()
		self.Session.configure( bind = self.Engine )	
		self.SessionInstance = self.Session()

	def AddPatch( self, name, title, url, html_data = '' ):
		patch = Patch( name, title, url, html_data )
		self.SessionInstance.add ( patch )
		return patch

	def AddCVE( self, patch, cve_string, name ):
		cve = CVE( cve_string, name )
		if patch:
			patch.cves.append( cve )
		else:
			self.SessionInstance.add( cve )
		return cve

	def AddDownload( self, patch, operating_system, name, url, filename, maximum_security_impact, aggregate_severity_rating, bulletins_replaced ):
		download = Download( operating_system, name, url, filename, maximum_security_impact, aggregate_severity_rating, bulletins_replaced )
		if patch:
			patch.downloads.append( download )
		else:
			self.SessionInstance.add( download )
		return download

	def AddFile(self, download, operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path ):
		fileindex = FileIndex( operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path )
		if download:
			download.fileindexes.append( fileindex )
		else:
			self.SessionInstance.add( fileindex )
		return fileindex
		
		#print 'Retrieved:',session.query( Index ).filter_by( operating_system='os').first() 
		
	def __del__( self ):
		self.SessionInstance.commit()

if __name__ == '__main__':
	database = Database( 'test.db' )

	operating_system = "os"
	service_pack = "sp"
	filename = "fn"
	company_name = "company"
	version_string = "version"
	patch_identifier = "patch"
	full_path = "full"	

	maximum_security_impact = 'Remote Code Execution'
	aggregate_severity_rating = 'Critical'
	bulletins_replaced = 'MS08-011'

	patch = database.AddPatch( 'MS09-011', 'Vulnerability in Microsoft DirectShow Could Allow Remote Code Execution (961373)', 'http://www.microsoft.com/technet/security/bulletin/ms09-011.mspx' )
	download = database.AddDownload( patch, 'Microsoft Windows 2000 Service Pack 4', 'DirectX 8.1', 'http://download.microsoft.com/download/5/1/A/51A85157-C145-4C4C-8F15-546A564EA841/Windows2000-DirectX8-KB961373-x86-ENU.exe', 'Patches/Windows2000-DirectX8-KB961373-x86-ENU.exe', maximum_security_impact, aggregate_severity_rating, bulletins_replaced )
	database.AddFile( download, operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path )
	
	download = database.AddDownload( patch, 'Microsoft Windows 2000 Service Pack 4','DirectX 8.1', 'http://download.microsoft.com/download/5/1/A/51A85157-C145-4C4C-8F15-546A564EA841/Windows2000-DirectX8-KB961373-x86-ENU.exe', 'Patches/Windows2000-DirectX8-KB961373-x86-ENU.exe', maximum_security_impact, aggregate_severity_rating, bulletins_replaced )
	database.AddFile( download, operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path )

	database.AddDownload( patch, 'Microsoft Windows 2000 Service Pack 4', 'DirectX 8.1', 'http://download.microsoft.com/download/5/1/A/51A85157-C145-4C4C-8F15-546A564EA841/Windows2000-DirectX8-KB961373-x86-ENU.exe', 'Patches/Windows2000-DirectX8-KB961373-x86-ENU.exe', maximum_security_impact, aggregate_severity_rating, bulletins_replaced )
	database.AddDownload( patch, 'Microsoft Windows 2000 Service Pack 4', 'DirectX 8.1', 'http://download.microsoft.com/download/5/1/A/51A85157-C145-4C4C-8F15-546A564EA841/Windows2000-DirectX8-KB961373-x86-ENU.exe', 'Patches/Windows2000-DirectX8-KB961373-x86-ENU.exe', maximum_security_impact, aggregate_severity_rating, bulletins_replaced )
