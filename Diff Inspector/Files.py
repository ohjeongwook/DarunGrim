from sqlalchemy import create_engine,Table,Column,Integer,String,ForeignKey,MetaData
from sqlalchemy.orm import mapper
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base=declarative_base()
class Files(Base):
	__tablename__='Files'
	id=Column(Integer, primary_key=True)
	filename=Column(String)
	version=Column(String)
	full_path=Column(String)

	def __init__(self,filename,version,full_path):
		self.filename=filename
		self.version=version
		self.full_path=full_path
	def __repr__(self):
		return "<Files('%s','%s','%s')>" % (self.filename, self.version, self.full_path)
