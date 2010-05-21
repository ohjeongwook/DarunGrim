import dircache
import os.path
from sqlalchemy import create_engine,Table,Column,Integer,String,ForeignKey,MetaData
from sqlalchemy.orm import mapper
from sqlalchemy.orm import sessionmaker
from Files import *

from sqlalchemy.interfaces import PoolListener 
class SetTextFactory(PoolListener): 
	def connect(self,dbapi_con,con_record): 
		dbapi_con.text_factory=str 

engine=create_engine('sqlite:///Files.db',listeners=[SetTextFactory()]) 

Session=sessionmaker(bind=engine)
session=Session()
last_row=None
for row in session.query(Files,Files.filename,Files.version,Files.full_path).order_by(Files.filename,Files.version):
	if last_row and last_row.filename==row.filename and last_row.version!=row.version:
		diff_filename="Diffs\\"+row.filename+'-'+last_row.version+'-'+row.version+".dgf"
		print 'DarunGrim2C.exe -f '+'"'+last_row.full_path+'" '+'"'+row.full_path+'" "'+diff_filename+'"'
	last_row=row
