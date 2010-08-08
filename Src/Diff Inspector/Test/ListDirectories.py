import dircache
import os.path
from sqlalchemy import create_engine,Table,Column,Integer,String,ForeignKey,MetaData
from sqlalchemy.orm import mapper
from sqlalchemy.orm import sessionmaker
from Files import *

def SearchDirectory(session,directory,whitelist):
	for file in dircache.listdir(directory):
		if file in whitelist:
			continue
		full_path=os.path.join(directory,file)
		if os.path.isdir(full_path):
			#print 'Directory',full_path
			SearchDirectory(session,full_path,whitelist)
		else:
			try:
				fd=open(full_path)
				if fd.read(2)=='MZ':
					path_elements=full_path.split('\\')
					filename=path_elements[-1]
					version=path_elements[-2]
					print filename.lower(),version,full_path
					session.add(Files(filename,version,full_path))
				fd.close()
			except:
				pass

engine=create_engine('sqlite:///Files.db',echo=True)
"""
metadata=MetaData()
FilesTable=Table('Files',metadata,
	Column('id',Integer,primary_key=True),
	Column('Filename',String),
	Column('Version',String),
	Column('FullPath',String))
mapper(Files,FilesTable)
""" 
metadata=Base.metadata
metadata.create_all(engine)

Session=sessionmaker(bind=engine)
session=Session()
SearchDirectory(session,r'T:\mat\Projects\Binaries',['.svn'])
session.commit()

