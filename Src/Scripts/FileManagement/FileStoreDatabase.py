import sqlalchemy
from sqlalchemy import Table, Column, Integer, String, Binary, DateTime, MetaData, ForeignKey
from sqlalchemy.orm import mapper, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import mapper, sessionmaker, aliased
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, backref
from sqlalchemy import and_, between

import datetime

Base=declarative_base()
from FileStore import *

class Patch(Base):
	__tablename__='patches'

	id=Column(Integer, primary_key=True)
	name=Column(String, index=True)
	title=Column(String)
	url=Column(String)
	html_data=Column(Binary)

	def __init__(self, name, title, url, html_data):
		self.name=name
		self.title=title
		self.url=url
		self.html_data=html_data

	def __repr__(self):
		return "<Patches('%s','%s','%s')>" % (self.name, self.title, self.url)

class Session(Base):
	__tablename__='session'
	id=Column(Integer, primary_key=True)
	name=Column(String, index=True)
	description=Column(String)
	src=Column(Integer)
	dst=Column(Integer)
	result=Column(String)

	def __init__(self, name, description, src, dst, result):
		self.name=name
		self.description=description
		self.src=src
		self.dst=dst
		self.result=result

	def __repr__(self):
		return "<Session('%s','%s','%d',%d','%s')>" % (self.name, self.description, self.src, self.dst, self.result)

class CVE(Base):
	__tablename__='cves'
	id=Column(Integer, primary_key=True)
	cve_string=Column(String, index=True)
	name=Column(String)

	patch_id=Column(Integer, ForeignKey('patches.id'))
	patches=relationship(Patch, backref=backref('cves', order_by=id))

	def __init__(self, cve_string, name):
		self.cve_string=cve_string
		self.name=name

	def __repr__(self):
		return "<CVEs('%s','%s')>" % (self.cve_string, self.name)

class Download(Base):
	__tablename__='downloads'
	id=Column(Integer, primary_key=True)
	operating_system=Column(String)
	label=Column(String)
	url=Column(String)
	filename=Column(String)
	maximum_security_impact=Column(String)
	aggregate_severity_rating=Column(String)
	bulletins_replaced=Column(String)

	patch_id=Column(Integer, ForeignKey('patches.id'))
	patches=relationship(Patch, backref=backref('downloads', order_by=id))

	def __init__(self, operating_system, label, url, filename, maximum_security_impact, aggregate_severity_rating, bulletins_replaced):
		self.operating_system=operating_system
		self.label=label
		self.url=url
		self.filename=filename
		self.maximum_security_impact=maximum_security_impact
		self.aggregate_severity_rating=aggregate_severity_rating
		self.bulletins_replaced=bulletins_replaced

	def __repr__(self):
		return "<Downloads('%s','%s','%s')>" % (self.label, self.url, self.filename)

class FileIndex(Base):
	__tablename__='fileindexes'

	id=Column(Integer, primary_key=True)
	operating_system=Column(String)
	arch=Column(String)
	service_pack=Column(String)
	filename=Column(String, index=True)
	company_name=Column(String)
	version_string=Column(String)
	patch_identifier=Column(String) #ex) MS09-011
	version_number=Column(String)
	release_plan=Column(String)
	src_full_path=Column(String, index=True)
	full_path=Column(String)
	ctime=Column(DateTime, index=True)
	mtime=Column(DateTime, index=True)
	added_time=Column(DateTime, index=True)
	md5=Column(String(length=16), index=True)
	sha1=Column(String(length=20), index=True)

	download_id=Column(Integer, ForeignKey('downloads.id'))
	downloads=relationship(Download, backref=backref('fileindexes', order_by=id))

	def __init__(self, arch, operating_system, service_pack, filename, company_name, version_string, patch_identifier, src_full_path, full_path, ctime, mtime, added_time, md5, sha1):
		self.arch=arch
		self.operating_system=operating_system
		self.service_pack=service_pack
		self.filename=filename
		self.company_name=company_name
		self.version_string=version_string
		self.patch_identifier=patch_identifier

		#Parser version_string
		version_string_parted=version_string.split(" (")
		if len(version_string_parted) == 2:
			(self.version_number, description)=version_string_parted
			for part in description.split('.'):
				for part2 in part.split('_'):
					if part2 == 'qfe' or part2 == 'gdr':
						self.release_plan=part2

					elif part2 in [ 'xpsp', 'vista', 'srv03' ]:
						self.operating_system=part2

					elif part2[0:2] == 'sp':
						self.service_pack=part2

		self.src_full_path=src_full_path
		self.full_path=full_path
		self.ctime=ctime
		self.mtime=mtime
		self.added_time=added_time
		self.md5=md5
		self.sha1=sha1

	def GetVersionDetailList(self):
		(os_string, sp_string, os_type, os_code, build_number)=self.ParseVersionString(self.version_string)
		return (self.id, self.full_path,os_string, sp_string, os_type, os_code, build_number)

	def GetVersionDetail(self):
		(id, full_path, os_string, sp_string, os_type, os_code, build_number)=self.GetVersionDetailList()
		file_entry={}
		file_entry['id']=id
		file_entry['full_path']=full_path
		file_entry['os_code']=os_code
		file_entry['os_string']=os_string
		file_entry['sp_string']=sp_string
		file_entry['os_type']=os_type
		file_entry['build_number']=build_number
		return file_entry

	def ParseVersionString(self, version_string):
		main_parts=version_string.split(' ')

		identifier=''
		version=''
		if len(main_parts) == 1:
			version=main_parts[0]
		elif len(main_parts) == 2:
			(version, identifier)=main_parts

		#### Version
		version_parts=version.split('.')

		os_code=''
		build_number=''
		if len(version_parts) > 3:
			os_code=version_parts[0]+'.'+version_parts[1]+'.'+version_parts[2]
			build_number=version_parts[3]


		#### Distro
		dot_pos=identifier.find(".")
		distro=''
		if dot_pos >= 0:
			distro=identifier[:dot_pos]
		distro=distro[1:]
		distro_parts=distro.split('_')
		os_string=''
		sp_string=''
		os_type=''
		if len(distro_parts) == 2:
			os_string=distro_parts[0]
			if os_string == 'xpsp2':
				os_string='xpsp'
				sp_string='sp2'
			elif os_string == 'xpclnt':
				os_string='xpsp'

		elif len(distro_parts) == 3:
			os_string=distro_parts[0]
			sp_string=distro_parts[1]
			os_type=distro_parts[2]

		return (os_string, sp_string, os_type, os_code, build_number)

	def __repr__(self):
		return "<FileIndex('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')>" % (self.arch, self.operating_system, self.service_pack, self.filename, self.company_name, self.version_string, self.patch_identifier, self.version_number, self.release_plan, self.full_path)

class Tags(Base):
	__tablename__='tags'
	id=Column(Integer, primary_key=True)
	tag=Column(String)
	sha1=Column(String)

	def __init__(self, tag, sha1):
		self.tag=tag
		self.sha1=sha1

	def __repr__(self):
		return "<TAGS('%s','%s')>" % (self.tag, self.sha1)

class Project(Base):
	__tablename__='projects'
	id=Column(Integer, primary_key=True)
	name=Column(String)
	description=Column(String)

	def __init__(self, name, description):
		self.name=name
		self.description=description

	def __repr__(self):
		return "<Project('%s','%s')>" % (self.name, self.description)

class ProjectMember(Base):
	__tablename__='project_members'
	id=Column(Integer, primary_key=True)

	project_id=Column(Integer, ForeignKey('projects.id'))
	projects=relationship(Project, backref=backref('project_members', order_by=id))

	file_id=Column(Integer, ForeignKey('fileindexes.id'))
	fileindexes=relationship(FileIndex, backref=backref('project_members', order_by=id))

	def __init__(self, project_id, file_id):
		self.project_id=project_id
		self.file_id=file_id

	def __repr__(self):
		return "<ProjectMember('%d','%d')>" % (self.project_id, self.file_id)

class ProjectResult(Base):
	__tablename__='project_results'
	id=Column(Integer, primary_key=True)

	project_id=Column(Integer, ForeignKey('projects.id'))
	projects=relationship(Project, backref=backref('project_results', order_by=id))

	source_file_id=Column(Integer, ForeignKey('fileindexes.id'))
	#fileindexes=relationship(FileIndex, backref=backref('project_results', order_by=id))

	target_file_id=Column(Integer, ForeignKey('fileindexes.id'))
	#target_file=relationship(FileIndex, backref=backref('project_results', order_by=id))

	database_name=Column(String)

	def __init__(self, project_id, source_file_id, target_file_id, database_name):
		self.project_id=project_id
		self.source_file_id=source_file_id
		self.target_file_id=target_file_id
		self.database_name=database_name

	def __repr__(self):
		return "<ProjectMember('%d','%d','%d','%s')>" % (self.project_id, self.source_file_id, self.target_file_id, self.database_name)

class Database:
	DebugLevel=2
	def __init__(self, filename):
		echo=False
		if self.DebugLevel > 2:
			echo=True
			print 'filename=',filename

		self.Engine=sqlalchemy.create_engine('sqlite:///' + filename, echo=echo)

		metadata=Base.metadata
		metadata.create_all(self.Engine)

		self.Session=sessionmaker()
		self.Session.configure(bind=self.Engine)
		self.SessionInstance=self.Session()

	def AddPatch(self, name, title, url, html_data=''):
		patch=Patch(name, title, url, html_data)
		self.SessionInstance.add (patch)
		return patch

	def GetPatch(self, name):
		return self.SessionInstance.query(Patch).filter_by(name=name).first()

	def GetPatches(self):
		return self.SessionInstance.query(Patch).order_by(Patch.name).all()

	def GetPatchByID(self, id):
		return self.SessionInstance.query(Patch).filter_by(id=id).all()

	def GetPatchNameByID(self, id):
		for patch in self.SessionInstance.query(Patch).filter_by(id=id).all():
			return patch.name
		return ''

	def AddCVE(self, patch, cve_string, name):
		cve=CVE(cve_string, name)
		if patch:
			patch.cves.append(cve)
		else:
			self.SessionInstance.add(cve)
		return cve

	def AddDownload(self, patch, operating_system, name, url, filename, maximum_security_impact, aggregate_severity_rating, bulletins_replaced):
		download=Download(operating_system, name, url, filename, maximum_security_impact, aggregate_severity_rating, bulletins_replaced)
		if patch:
			patch.downloads.append(download)
		else:
			self.SessionInstance.add(download)
		return download

	def GetDownloadByFilename(self , filename):
		return self.SessionInstance.query(Download).filter_by(filename=filename).first()

	def GetDownloadByPatchID(self , patch_id):
		return self.SessionInstance.query(Download).filter_by(patch_id=patch_id).all()

	def GetSessions(self):
		SourceTags=aliased(Tags,name='SourceTags')
		TargetTags=aliased(Tags,name='TargetTags')

		SourceFileIndex=aliased(FileIndex,name='SourceFileIndex')
		TargetFileIndex=aliased(FileIndex,name='TargetFileIndex')

		query=self.SessionInstance.query(Session, SourceTags, TargetTags)
		query=query.outerjoin(SourceFileIndex, SourceFileIndex.id==Session.src)
		query=query.outerjoin(TargetFileIndex, TargetFileIndex.id==Session.dst)

		query=query.outerjoin(SourceTags, SourceFileIndex.sha1==SourceTags.sha1)
		query=query.outerjoin(TargetTags, TargetFileIndex.sha1==TargetTags.sha1)

		return query.all()

	def GetDownloads(self):
		return self.SessionInstance.query(Download).filter(~Download.id.in_(self.SessionInstance.query(FileIndex.download_id)))

	def GetDownloadID(self, id):
		return self.SessionInstance.query(Download).filter_by(id=id).all()

	def GetDownloadByID(self, id):
		return self.SessionInstance.query(Download).filter_by(id=id).all()

	def GetDownloadLabelByID(self, id):
		for download in self.GetDownloadID(id):
			return download.label
		return ''

	def GetFileByID(self, id):
		return self.SessionInstance.query(FileIndex).filter_by(id=id).all()

	def SelectBySubType(self, query, sub_type, sub_search_str):
		if sub_type and search_str:
			if sub_search_str == '*':
				search_str='%'
			elif sub_search_str:
				search_str='%'+sub_search_str+'%'	

			if sub_type == 'CompanyName':
				return query.filter(FileIndex.company_name.like(search_str))

		return query

	def SelectByDateRange(self, query, date_type, from_date_string, to_date_string):
		print from_date_string[6:10], from_date_string[0:2], from_date_string[3:5]
		from_date=datetime.date(int(from_date_string[6:10]), int(from_date_string[0:2]), int(from_date_string[3:5]))
		to_date=datetime.date(int(to_date_string[6:10]), int(to_date_string[0:2]), int(to_date_string[3:5]))

		if date_type == 'CreatedDate':
			return query.filter(between(FileIndex.ctime, from_date, to_date))
		elif date_type == 'ModifiedDate':
			return query.filter(between(FileIndex.mtime, from_date, to_date))
		elif date_type == 'AddedDate':
			return query.filter(between(FileIndex.added_time, from_date, to_date))
		return query	

	def GetFileBySHA1(self, sha1, sub_type , sub_search_str, date_type, from_date_string, to_date_string):
		query=self.SessionInstance.query(FileIndex).filter_by(sha1=sha1)
		
		if sub_type and sub_search_str:
			query=self.SelectBySubType(query, sub_type, sub_search_str)

		if date_type and from_date_string and to_date_string:
			query=self.SelectByDateRange(query, date_type, from_date_string, to_date_string)
		return query.all()

	def GetFileByMD5(self, md5, sub_type , sub_search_str, date_type, from_date_string, to_date_string):
		query=self.SessionInstance.query(FileIndex).filter_by(md5=md5)
		
		if sub_type and sub_search_str:
			query=self.SelectBySubType(query, sub_type, sub_search_str)

		if date_type and from_date_string and to_date_string:
			query=self.SelectByDateRange(query, date_type, from_date_string, to_date_string)
		return query.all()

	def GetFileNameByID(self, id):
		for file_index in self.SessionInstance.query(FileIndex).filter_by(id=id).all():
			return file_index.filename
		return ''

	def GetFileNameWithVersionByID(self, id):
		for file_index in self.SessionInstance.query(FileIndex).filter_by(id=id).all():
			return '%s: %s' % (file_index.filename, file_index.version_string)
		return ''

	def GetFileByCompanyFileName(self, company_name, filename):
		return self.SessionInstance.query(FileIndex).filter(and_(FileIndex.company_name==company_name, FileIndex.filename==filename)).all()

	def GetFileByFileName(self, filename):
		return self.SessionInstance.query(FileIndex).filter(FileIndex.filename==filename).all()

	def SearchFiles(self, filename, sub_type='', sub_search_str='', date_type='', from_date_string='', to_date_string=''):
		search_str=None
		if filename == '*':
			search_str='%'
		elif filename:
			search_str='%'+filename+'%'

		if search_str:
			query=self.SessionInstance.query(FileIndex,Tags).filter(FileIndex.filename.like(search_str))

			if sub_type and sub_search_str:
				query=self.SelectBySubType(query, sub_type, sub_search_str)

			if date_type and from_date_string and to_date_string:
				query=self.SelectByDateRange(query, date_type, from_date_string, to_date_string)

			return query.outerjoin(Tags, FileIndex.sha1==Tags.sha1).order_by(FileIndex.filename)
		return None

	def GetFileBySrcFullPathWildMatch(self, filename, sub_type , sub_search_str, date_type, from_date_string, to_date_string):
		query=self.SessionInstance.query(FileIndex).filter(FileIndex.src_full_path.like('%'+filename+'%'))

		if sub_type and sub_search_str:
			query=self.SelectBySubType(query, sub_type, sub_search_str)

		if date_type and from_date_string and to_date_string:
			query=self.SelectByDateRange(query, date_type, from_date_string, to_date_string)
		return query.order_by(FileIndex.src_full_path).all()

	def GetFiles(self):
		return self.SessionInstance.query(FileIndex).all()

	def GetFilesByCompanyName(self, company_name=None):
		return self.SessionInstance.query(FileIndex).filter(FileIndex.company_name==company_name).distinct().all()

	def GetFilesByTag(self, tag):
		rets=[]
		for (fileindex,tags) in self.SessionInstance.query(FileIndex,Tags).filter(FileIndex.sha1==Tags.sha1).filter(Tags.tag==tag).distinct().all():
			rets.append((fileindex,tags))
		return rets

	def GetFilesByCompanyFilename(self, company_name=None, filename=None):
		return self.SessionInstance.query(FileIndex).filter(and_(FileIndex.company_name==company_name, FileIndex.filename==filename)).all()

	def GetFileNames(self, company_name=None):
		tmp_rets=[]
		if company_name != None:
			tmp_rets=self.SessionInstance.query(FileIndex.filename).filter(FileIndex.company_name==company_name).distinct().all()
		else:
			tmp_rets=self.SessionInstance.query(FileIndex.filename).distinct().all()

		rets=[]
		for (name,) in tmp_rets:
			rets.append(name)

		return rets

	def GetCompanyNames(self):
		rets=[]

		for (name,) in self.SessionInstance.query(FileIndex.company_name).distinct().all():
			rets.append(name)

		return rets

	def GetTags(self):
		rets=[]

		for tag in self.SessionInstance.query(Tags).distinct().all():
			rets.append(tag)

		return rets

	def GetTagNames(self):
		names=[]

		for (tag,) in self.SessionInstance.query(Tags.tag).distinct().all():
			names.append(tag)

		return names

	def GetVersionStrings(self, company_name=None, filename=None):
		rets=[]
		if company_name !=None and filename != None:
			for (ret,) in self.SessionInstance.query(FileIndex.version_string).filter(and_(FileIndex.company_name==company_name, FileIndex.filename==filename)).distinct().all():
				rets.append(ret)
		else:
			for (ret,) in self.SessionInstance.query(FileIndex.version_string).distinct().all():
				rets.append(ret)
		return rets

	def GetVersionStringsWithIDs(self, company_name=None, filename=None):
		if company_name !=None and filename != None:
			return self.SessionInstance.query(FileIndex.id, FileIndex.version_string).filter(and_(FileIndex.company_name==company_name, FileIndex.filename==filename)).distinct().order_by(FileIndex.version_string).all()
	
		return self.SessionInstance.query(FileIndex.id, FileIndex.version_string).distinct().all()

	def GetFileByFileInfo(self, filename, company_name, version_string):
		return self.SessionInstance.query(FileIndex).filter(and_(FileIndex.filename==filename, FileIndex.company_name==company_name, FileIndex.version_string==version_string)).all()

	def GetFileByDownloadID(self, download_id):
		return self.SessionInstance.query(FileIndex).filter_by(download_id=download_id).all()

	def AddFile(self,
					download=None,
					arch='',
					operating_system='',
					service_pack='',
					filename='',
					company_name='',
					version_string='',
					patch_identifier='',
					src_full_path='',
					full_path='',
					ctime=0,
					mtime=0,
					added_time=0,
					md5 ='',
					sha1 ='',
					tags=[]
				):
		fileindex=FileIndex(arch,
							operating_system, 
							service_pack, 
							filename, 
							company_name, 
							version_string, 
							patch_identifier, 
							src_full_path, 
							full_path, 
							ctime, 
							mtime, 
							added_time, 
							md5, 
							sha1 
						)
		if download:
			download.fileindexes.append(fileindex)
		else:
			self.SessionInstance.add(fileindex)

		for tag in tags:
			tag=Tags(tag, sha1)
			self.SessionInstance.add(tag)
		return fileindex

	def UpdateTag(self,orig_tag,new_tag):
		for tag in self.SessionInstance.query(Tags).filter(Tags.tag==orig_tag).all():
			tag.tag=new_tag
		self.Commit()

	def UpdateFile(self,
					download=None,
					arch='',
					operating_system='',
					service_pack='',
					filename='',
					company_name='',
					version_string='',
					patch_identifier='',
					src_full_path='',
					full_path='',
					ctime=0,
					mtime=0,
					added_time=0,			
					md5 ='',
					sha1 =''
				):
		for file in self.SessionInstance.query(FileIndex).filter(FileIndex.sha1==sha1).all():
			file.download=download
			file.arch=arch
			file.operating_system=operating_system
			file.service_pack=service_pack
			file.filename=filename
			file.company_name=company_name
			file.version_string=version_string
			file.patch_identifier=patch_identifier
			file.src_full_path=src_full_path
			file.full_path=full_path
			file.ctime=ctime
			file.mtime=mtime
			file.added_time=added_time
			file.md5=md5
			file.sha1=sha1
		self.Commit()

	def UpdateFileByObject(self,
					file,
					download=None,
					arch='',
					operating_system='',
					service_pack='',
					filename='',
					company_name='',
					version_string='',
					patch_identifier='',
					src_full_path='',
					full_path='',
					ctime=0,
					mtime=0,
					added_time=0,
					md5 ='',
					sha1 ='',
					tags=[]
				):
		file.download=download
		self.arch=arch
		file.operating_system=operating_system
		file.service_pack=service_pack
		file.filename=filename
		file.company_name=company_name
		file.version_string=version_string
		file.patch_identifier=patch_identifier
		file.src_full_path=src_full_path
		file.full_path=full_path
		file.ctime=ctime
		file.mtime=mtime
		file.added_time=added_time
		file.md5=md5
		file.sha1=sha1
		self.Commit()

		for tag in tags:
			tag=Tags(tag, sha1)
			self.SessionInstance.add(tag)

	def AddSession(self, name, description, src, dst, result):
		session=Session(name, description, src, dst, result)
		self.SessionInstance.add(session)
		self.Commit()

	##### Project related methods #####
	def AddProject(self, name, description=''):
		project=Project(name, description)
		self.SessionInstance.add(project)
		return project

	def GetProjectNames(self):
		return self.SessionInstance.query(Project.name).all()

	def GetProjects(self):
		return self.SessionInstance.query(Project).order_by(Project.id).all()

	def GetProject(self, project_id):
		return self.SessionInstance.query(Project).filter_by(id=project_id).first()

	def RemoveProject(self, project_id):
		project=self.SessionInstance.query(Project).filter_by(id=project_id).first()
		self.SessionInstance.delete(project)
		self.Commit()
		return project

	def UpdateProject(self, project_id, name, description):
		project=self.SessionInstance.query(Project).filter_by(id=project_id).first()
		project.name=name
		project.description=description
		self.Commit()
		return project

	def AddToProject(self, project_id, id=None):
		if self.DebugLevel > 2:
			print 'AddToProject', project_id, id

		if id:
			project_members=ProjectMember(project_id, id)
			ret=self.SessionInstance.query(ProjectMember).filter_by(project_id=project_id).filter_by(file_id=id).all()
			if len(ret) == 0:
				self.SessionInstance.add(project_members)
			else:
				if self.DebugLevel > 1:
					print 'Duplicate', project_id, id, ret

	def GetProjectMembers(self, project_id):
		return self.SessionInstance.query(ProjectMember).filter_by(project_id=project_id).all()

	def RemoveProjectMember (self, project_member_id):
		project_member=self.SessionInstance.query(ProjectMember).filter_by(id=project_member_id).first()
		self.SessionInstance.delete(project_member)
		self.Commit()

	def AddProjectResult(self, project_id, source_file_id, target_file_id, database_name):
		project_result=ProjectResult(project_id, source_file_id, target_file_id, database_name)
		ret=self.SessionInstance.query(ProjectResult).filter(and_(ProjectResult.project_id == project_id, ProjectResult.source_file_id == source_file_id, ProjectResult.target_file_id == target_file_id, ProjectResult.database_name == database_name)).all()
		if len(ret) == 0:
			self.SessionInstance.add(project_result)
			self.Commit()
		else:
			if self.DebugLevel > 1:
				print 'Duplicate', project_id, source_file_id, target_file_id, database_name, ret

	def GetProjectResults(self, project_id=None):
		if project_id:
			return self.SessionInstance.query(ProjectResult).filter_by(project_id=project_id).all()
		else:
			return self.SessionInstance.query(ProjectResult).all()

	def Commit(self):
		try:
			self.SessionInstance.commit()
			return True
		except:
			if self.DebugLevel > -1:
				print 'Failed to Commit'
				import traceback
				traceback.print_exc()
			self.SessionInstance.rollback()
			return False

class Analyzer:
	DebugLevel=0
	def __init__(self, database_name=None, database=None):
		if database_name:
			self.DatabaseName=database_name
			self.Database=Database(self.DatabaseName)
		elif database:
			self.Database=database

	def GetPatchFileNamePairs(self):
		patch_file_name_pairs=[]
		for patch in self.Database.GetPatches():
			if self.DebugLevel > 2:
				print patch.name
			filenames={}
			for download in self.Database.GetDownloadByPatchID(patch.id):
				if self.DebugLevel > 2:
					print '\t',download.filename
				for fileindex in self.Database.GetFileByDownloadID(download.id):
					if self.DebugLevel > 2:
						print '\t\t',fileindex.filename
					filenames[fileindex.filename]=1
			for filename in filenames.keys():
				patch_file_name_pairs.append((patch.name, filename))
		return patch_file_name_pairs

	def GetPatchHistory(self, filename):
		patch_infos_by_patch_name={}
		
		process_patches={}
		for entry in self.Database.GetFileByFileName(filename):
			patch_name='Default'
			if entry.downloads and entry.downloads.patches:
				patch_name=entry.downloads.patches.name
		
			if not patch_infos_by_patch_name.has_key(patch_name):
				patch_infos_by_patch_name[patch_name]=[]
				
			if not process_patches.has_key(entry.version_string):
				process_patches[entry.version_string]=1
				patch_infos_by_patch_name[patch_name].append(entry.GetVersionDetail())

		sorted_patch_infos=[]
		patch_names=patch_infos_by_patch_name.keys()
		patch_names.sort()
		patch_names.reverse()
		for patch_name in patch_names:
			sorted_patch_infos.append((patch_name, patch_infos_by_patch_name[patch_name]))

		return sorted_patch_infos

	def GetFileHistory(self, filename):
		return self.Database.GetFileByFileName(filename)

	def DumpPatchInfos(self, patch_infos):
		version_strings=patch_infos.keys()
		version_strings.sort()

		for version_string in version_strings:
			patch_name=patch_infos[version_string]
			if self.DebugLevel > 2:
				print patch_name, version_string
			(os_string, sp_string, os_type, os_code, build_number)=ParseVersionString(version_string)
			if self.DebugLevel > 2:
				print '\t',os_string, sp_string, os_type, os_code, build_number

	def FindPatchTarget(self, file_patch_info, target_patch_name, target_file_entry):
		maximum_match_patch_name=None
		maximum_match_file_entry=None
		maximum_point=0
		index=0
		for (patch_name, file_entries) in file_patch_info:
			if self.DebugLevel > 2:
				print 'Comparing',target_patch_name,patch_name
			if cmp(target_patch_name, patch_name) > 0 :
				if self.DebugLevel > 2:
					print 'Check',patch_name

				for file_entry in file_entries:
					weight=len(file_patch_info)
					point=weight * (len(file_patch_info) - index) * 30

					if not target_file_entry.has_key('os_code') or (target_file_entry[ 'os_code' ] == file_entry[ 'os_code' ]):
						point += weight * 20
						if not target_file_entry.has_key('os_string') or (target_file_entry[ 'os_string' ] == file_entry[ 'os_string' ]):
							point += weight * 10
							if not target_file_entry.has_key('sp_string') or (target_file_entry[ 'sp_string' ] == file_entry[ 'sp_string' ]):
								point += weight * 5
								if not target_file_entry.has_key('os_type') or (target_file_entry[ 'os_type' ] == file_entry[ 'os_type' ]):
									point += weight

					if point > maximum_point:
						if self.DebugLevel > 2:
							print 'Check',file_entry,point
						maximum_match_patch_name=patch_name
						maximum_match_file_entry=file_entry
						maximum_point=point
			index += 1
		return (maximum_match_patch_name, maximum_match_file_entry, maximum_point)

	def GetPatchPairsForAnalysis(self, filename=None, id=None, patch_name=None):
		file_patch_info=self.GetPatchHistory(filename)
		target_file_entry=None

		if id:
			file_entry=self.Database.GetFileByID(id)
			if file_entry and len(file_entry) > 0:
				target_file_entry=file_entry[0].GetVersionDetail()
				print 'target_file_entry=', target_file_entry

		patch_pairs_for_analysis=[]
		for (current_patch_name, file_entries) in file_patch_info:		
			if patch_name and current_patch_name != patch_name:
				continue

			maximum_point=0
			maximum_entry=None

			if target_file_entry:
				target_file_entries=[ target_file_entry ]
			else:
				target_file_entries=file_entries

			for file_entry in target_file_entries:
				(matched_patch_name, matched_file_entry, match_point)=self.FindPatchTarget(file_patch_info, current_patch_name, file_entry)
				if match_point > maximum_point:
					maximum_entry=(matched_patch_name, file_entry, matched_file_entry, match_point)
					maximum_point=match_point

			if maximum_entry:
				(matched_patch_name, file_entry, matched_file_entry, match_point)=maximum_entry
				if self.DebugLevel > 2:
					print '='*80
					print current_patch_name
					print file_entry
					print matched_patch_name
					print matched_file_entry
				patch_pairs_for_analysis.append((current_patch_name, file_entry, matched_patch_name, matched_file_entry))

		return patch_pairs_for_analysis

if __name__ == '__main__':
	from optparse import OptionParser
	import sys

	parser=OptionParser()
	parser.add_option('-d','--dump',
					dest='dump',help="Dump file information", 
					action="store_true", default=False, 
					metavar="DUMP")

	parser.add_option('-t','--tag',
					dest='tag',help="Set tag information to retrieve", 
					default='', 
					metavar="TAG")

	parser.add_option('-s','--add_session',
					dest='add_session',help="Add a diffing session", 
					action="store_true", default=False, 
					metavar="ADD_PROJECT")

	parser.add_option('-D','--database',
					dest='database',help="Set database name", 
					default="index.db", 
					metavar="DATABASE")

	(options,args)=parser.parse_args()

	database=Database(options.database)
	if options.dump:
		if options.tag:
			pass
		else:
			company_names=database.GetCompanyNames()

			for company_name in company_names:
				print company_name
				for filename in database.GetFileNames(company_name):
					print '\t', filename
					for version_string in database.GetVersionStrings(company_name, filename):
						print '\t\t',version_string

	elif options.add_session:
		name='Test'
		description='Test session'
		src=1
		dst=2
		result='test.dgf'
		database.AddSession(name, description, src, dst, result)

		for (session,source_tag,dst_tag) in database.GetSessions():
			print '*' * 5
			print session.name
			print database.GetFileNameByID(session.src)
			print database.GetFileNameByID(session.dst)

	"""
		arch=''
		operating_system="os"
		service_pack="sp"
		filename="fn"
		company_name="company"
		version_string="version"
		patch_identifier="patch"
		full_path="full"

		maximum_security_impact='Remote Code Execution'
		aggregate_severity_rating='Critical'
		bulletins_replaced='MS08-011'

		patch=database.AddPatch('MS09-011', 'Vulnerability in Microsoft DirectShow Could Allow Remote Code Execution (961373)', 'http://www.microsoft.com/technet/security/bulletin/ms09-011.mspx')
		download=database.AddDownload(patch, 'Microsoft Windows 2000 Service Pack 4', 'DirectX 8.1', 'http://download.microsoft.com/download/5/1/A/51A85157-C145-4C4C-8F15-546A564EA841/Windows2000-DirectX8-KB961373-x86-ENU.exe', 'Patches/Windows2000-DirectX8-KB961373-x86-ENU.exe', maximum_security_impact, aggregate_severity_rating, bulletins_replaced)
		database.AddFile(download, arch, operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path)

		download=database.AddDownload(patch, 'Microsoft Windows 2000 Service Pack 4','DirectX 8.1', 'http://download.microsoft.com/download/5/1/A/51A85157-C145-4C4C-8F15-546A564EA841/Windows2000-DirectX8-KB961373-x86-ENU.exe', 'Patches/Windows2000-DirectX8-KB961373-x86-ENU.exe', maximum_security_impact, aggregate_severity_rating, bulletins_replaced)
		database.AddFile(download, arch, operating_system, service_pack, filename, company_name, version_string, patch_identifier, full_path)

		database.AddDownload(patch, 'Microsoft Windows 2000 Service Pack 4', 'DirectX 8.1', 'http://download.microsoft.com/download/5/1/A/51A85157-C145-4C4C-8F15-546A564EA841/Windows2000-DirectX8-KB961373-x86-ENU.exe', 'Patches/Windows2000-DirectX8-KB961373-x86-ENU.exe', maximum_security_impact, aggregate_severity_rating, bulletins_replaced)
		database.AddDownload(patch, 'Microsoft Windows 2000 Service Pack 4', 'DirectX 8.1', 'http://download.microsoft.com/download/5/1/A/51A85157-C145-4C4C-8F15-546A564EA841/Windows2000-DirectX8-KB961373-x86-ENU.exe', 'Patches/Windows2000-DirectX8-KB961373-x86-ENU.exe', maximum_security_impact, aggregate_severity_rating, bulletins_replaced)
		database.Commit()

	if "GetPatch" in Tests:
		print 'MS09-018',database.GetPatch('MS09-018')
		print 'MS09-0999',database.GetPatch('MS09-099')

	if "RenameFiles" in Tests:
		for file in database.GetFiles():
			try:
				#file.full_path=file.full_path.replace("T:\\mat\\Projects\\", "")
				file.full_path=file.full_path.replace("Binaries\\", "")
			except:
				pass
		database.Commit()

		analyzer=Analyzer(database_name=r'adobe.db')
		for row in analyzer.GetPatchHistory(filename):
			(patch_name, patch_infos)=row
			print patch_name
			for patch_info in patch_infos:
				print '-'*50
				for (key,value) in patch_info.items():
					print '\t',key,value
	

	"""