import sqlalchemy
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey
from sqlalchemy.orm import mapper, sessionmaker

class Index(object):
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
		return "<Index('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )>" % ( self.operating_system, self.service_pack, self.filename, self.company_name, self.version_string, self.patch_identifier, self.version_number, self.release_plan, self.full_path )

class Database:
	DebugLevel = 3
	def __init__( self, filename ):
		echo = False
		if self.DebugLevel > 2:
			echo = True
		self.Engine = sqlalchemy.create_engine( 'sqlite:///' + filename, echo = echo )
		metadata = MetaData()

		self.IndexTable = Table( 'FileIndex', metadata, 
			Column('id', Integer, primary_key = True ),
			Column('operating_system', String ),
			Column('service_pack', String ),
			Column('filename', String ),
			Column('company_name', String ),
			Column('version_string', String ),
			Column('patch_identifier', String ), #ex) MS09-011
			Column('version_number', String ),
			Column('release_plan', String ),
			Column('full_path', String )
		)
		metadata.create_all( self.Engine )
		mapper( Index, self.IndexTable )
		
		self.Session = sessionmaker()
		self.Session.configure( bind = self.Engine )	
		self.SessionInstance = self.Session()

	def Add(self, operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path ):
		new_record = Index( operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path )
		self.SessionInstance.add ( new_record )
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
	database.Add( operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path )