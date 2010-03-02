!include "..\Paths.Mak"
PROC=DarunGrim2

LOCAL_LIB_DIR=..\Lib
DIFF_ENGINE_DIR=..\DiffEngine
CPP=cl.exe

#-DINTERNAL_SERVER: For testing internal server
#-DEXTERNAL_SERVER="\"DarunGrim.exe\"" 
CPP_PROJ=/nologo /D WINDOWS /D "__NT__" /D "__IDP__" /D MAXSTR=1024 /D "WIN32" /D "_USRDLL" /D "_CRT_SECURE_NO_DEPRECATE" /D "USE_DANGEROUS_FUNCTIONS" /D "_USE_IDA_SDK_49_OR_UPPER" /Fo$(F) /c /EHsc -D_MT /WX -I"$(I)" -I$(ZLIB_INC) -I$(ZLIB_WRAPPER_DIR) -I. -MTd /Zi -I$(DIFF_ENGINE_DIR) -I$(LOCAL_LIB_DIR) -I$(IDA_LIB_DIR) -Dprintf=msg -I$(SQLITE_DIR_INC) -I$(DBWRAPPER_DIR) -I$(DEBUG_LIB_DIR)
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib user32.lib advapi32.lib version.lib $(ZLIB_LIB)\zlib.lib $(SQLITE_DIR_LIB)\sqlite3.lib "$(IDALIB)" $(LIBS) /NODEFAULTLIB:LIBC /NODEFAULTLIB:LIBCD /nologo /dll /out:"$(BINARY)" /implib:$(F)$(PROC)$(A) /libpath:"$(L)" /export:PLUGIN /VERSION:0.1 /debug

I=$(IDA_SDK_DIR)\include\\
L=$(IDA_SDK_DIR)\libvc.w32\                   # libraries directory
R=bin\                         # results directory
F=.\vc.w32\                          # object files directory
SUBDIR=
PLUGIN=.plw                          # PLUGIN extension
O=.obj                               # object file extension
A=.lib                               # library file extension
RM=erase /q                          # File Remover
IDALIB=$(L)ida$(A)

OBJS=$(F)DataBaseWriter$(O) $(F)IDAAnalysis$(O) $(F)fileinfo$(O) $(F)md5$(O) $(F)SharedMemory$(O) $(F)SharedSocket$(O) $(F)SocketOperation.obj $(F)ProcessUtils$(O) $(F)IDAVerifier$(O) $(F)dprintf$(O) $(F)$(PROC)$(O) $(OUTDIR)\Main.res

BINARY=$(R)$(SUBDIR)$(PROC)$(PLUGIN)

all: $(R)$(SUBDIR) $(F) "$(BINARY)"

clean:
	-@$(RM) $(F)*$(O)
	-@$(RM) $(F)*$(A)
	-@$(RM) $(F)*.exp
	-@$(RM) "$(BINARY)"

distclean: clean
	-@$(RM) $(F)*
	rmdir $(F)

$(F):
	if not exist $(F) mkdir $(F)

$(R)$(SUBDIR):
	if not exist $(R)$(SUBDIR) mkdir $(R)$(SUBDIR)

.c{$(F)}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $< 
<<

$(F)dprintf$(O): $(DEBUG_LIB_DIR)\dprintf.cpp
    $(CPP) $(CPP_PROJ) $(DEBUG_LIB_DIR)\dprintf.cpp  

$(F)SharedMemory.obj: $(LOCAL_LIB_DIR)\SharedMemory.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\SharedMemory.cpp

$(F)SharedSocket.obj: $(LOCAL_LIB_DIR)\SharedSocket.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\SharedSocket.cpp
   
$(F)md5$(O): $(LOCAL_LIB_DIR)\md5.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\md5.cpp

$(F)fileinfo$(O): $(LOCAL_LIB_DIR)\fileinfo.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\fileinfo.cpp

$(F)IDAAnalysis$(O): $(IDA_LIB_DIR)\IDAAnalysis.cpp
    $(CPP) $(CPP_PROJ) $(IDA_LIB_DIR)\IDAAnalysis.cpp    

$(F)SocketOperation$(O): $(LOCAL_LIB_DIR)\SocketOperation.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\SocketOperation.cpp  

$(F)ProcessUtils$(O): $(LOCAL_LIB_DIR)\ProcessUtils.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\ProcessUtils.cpp

$(F)IDAVerifier$(O): $(LOCAL_LIB_DIR)\IDAVerifier.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\IDAVerifier.cpp

$(F)DataBaseWriter$(O): $(LOCAL_LIB_DIR)\DataBaseWriter.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\DataBaseWriter.cpp

$(OUTDIR)\Main.res: ..\UI\Main.rc 
    rc -r /fo $(OUTDIR)\Main.res -IC:\WTL80\include ..\UI\Main.rc

.cpp{$(F)}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $< 
<<

.cpp{}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $< 
<<

"$(BINARY)" : $(F) $(OBJS)
	$(LINK32) @<<
  $(LINK32_FLAGS) $(OBJS) 
<<
