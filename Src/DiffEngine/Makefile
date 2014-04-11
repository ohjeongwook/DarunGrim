# Nmake macros for building Windows 32-Bit apps

!include <Win32.Mak>
!include "..\Paths.Mak"

DIFF_ENGINE=..\DiffEngine
LIB_DIR=..\Lib

cflags=$(cflags) -I$(SQLITE_DIR_INC)
cflags=$(cflags) -I$(DEBUG_LIB_DIR)
cflags=$(cflags) -I$(REGISTRY_API_DIR)
cflags=$(cflags) -I$(IDA_LIB_DIR)
cflags=$(cflags) -I$(LOGGER_DIR)
cflags=$(cflags) -I$(GRAPHVIZ_INTERFACE)
cflags=$(cflags) -I"\mat\Projects\Lib\GraphViz\include"
cflags=$(cflags) -D_CRT_SECURE_NO_WARNINGS
cflags=$(cflags) -I\mat\Projects\ResearchTools\Graphics\GraphVizInterface\Src
cflags=$(cflags) -I$(DIFF_LIB_DIR)
cflags=$(cflags) -I$(DIFF_ENGINE)
cflags=$(cflags) -I$(ZLIB_INC)
cflags=$(cflags) -I$(ZLIB_WRAPPER_DIR)
cflags=$(cflags) -I$(DBWRAPPER_DIR) 
cflags=$(cflags) -I$(LIB_DIR) 
cflags=$(cflags) -I$(XGETOPT_DIR) 
cflags=$(cflags) $(cdebug) $(cvarsmt)
#cflags=$(cflags) /FICommon.h
cflags=$(cflags) /EHsc
cflags=$(cflags) /Zi
cflags=$(cflags) -Ic:\WTL\include
cflags=$(cflags) /Ddprintf=printf
cflags=$(cflags) /D_SECURE_SCL=0 #Performance Improvement by turning off checked iterator
cvars=

conlibs=$(conlibs) user32.lib odbc32.lib odbccp32.lib comctl32.lib advapi32.lib
dlllflags=$(dlllflags) advapi32.lib

!IFDEF NODEBUG
conlibs=$(conlibs) LIBCMT.LIB /NODEFAULTLIB:msvcrt.lib
!ELSE
conflags=$(conflags) /DEBUG
conlibs=$(conlibs) LIBCMTD.LIB /NODEFAULTLIB:Libcmt.lib /NODEFAULTLIB:msvcrt.lib
!ENDIF

python_include=-IC:\Python26\include -D__WIN32__
python_lflags =/LIBPATH:C:\Python26\libs ws2_32.lib user32.lib /DEBUG /NODEFAULTLIB:msvcrt.lib

all: $(OUTDIR) $(OUTDIR)\DarunGrim2C.exe $(OUTDIR)\_DiffEngine.pyd $(OUTDIR)\Test.exe

#----- If OUTDIR does not exist, then create directory
$(OUTDIR) :
    if not exist "$(OUTDIR)/$(NULL)" mkdir $(OUTDIR)

$(OUTDIR)\IDAClientManager.obj: $(DIFF_ENGINE)\IDAClientManager.cpp $(DIFF_ENGINE)\DataStructure.h
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\IDAClientManager.cpp

$(OUTDIR)\dprintf.obj: $(DEBUG_LIB_DIR)\dprintf.cpp 
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DEBUG_LIB_DIR)\dprintf.cpp

$(OUTDIR)\OneIDAClientManager.obj: $(DIFF_ENGINE)\OneIDAClientManager.cpp $(DIFF_ENGINE)\DataStructure.h $(DBWRAPPER_DIR)\DBWrapper.h
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\OneIDAClientManager.cpp

$(OUTDIR)\DiffMachine.obj: $(DIFF_ENGINE)\DiffMachine.cpp $(DIFF_ENGINE)\DataStructure.h $(DBWRAPPER_DIR)\DBWrapper.h
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\DiffMachine.cpp

$(OUTDIR)\SharedMemory.obj: $(LIB_DIR)\SharedMemory.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SharedMemory.cpp

$(OUTDIR)\SharedSocket.obj: $(LIB_DIR)\SharedSocket.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SharedSocket.cpp

$(OUTDIR)\ProcessUtils.obj: $(LIB_DIR)\ProcessUtils.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\ProcessUtils.cpp

$(OUTDIR)\SocketOperation.obj: $(LIB_DIR)\SocketOperation.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SocketOperation.cpp

$(OUTDIR)\LogOperation.obj: $(LOGGER_DIR)\LogOperation.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LOGGER_DIR)\LogOperation.cpp

$(OUTDIR)\RegistryUtil.obj: $(REGISTRY_API_DIR)\RegistryUtil.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(REGISTRY_API_DIR)\RegistryUtil.cpp

$(OUTDIR)\Diff.obj: $(DIFF_LIB_DIR)\Diff.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_LIB_DIR)\Diff.cpp

$(OUTDIR)\Varray.obj: $(DIFF_LIB_DIR)\Varray.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_LIB_DIR)\Varray.cpp

$(OUTDIR)\DatabaseWriter.obj: $(LIB_DIR)\DataBaseWriter.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\DataBaseWriter.cpp

$(OUTDIR)\XGetopt.obj: $(XGETOPT_DIR)\XGetopt.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(XGETOPT_DIR)\XGetopt.cpp

$(OUTDIR)\DarunGrim.obj: DarunGrim.cpp DarunGrim.h
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" DarunGrim.cpp

$(OUTDIR)\DarunGrim2C.obj: $(DIFF_ENGINE)\DarunGrim2C.cpp $(DIFF_ENGINE)\DataStructure.h DiffMachine.h DiffMachine.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\DarunGrim2C.cpp

$(OUTDIR)\DarunGrim2C.exe: $(OUTDIR) $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(ZLIB_LIB)\zlib.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DarunGrim2C.obj $(OUTDIR)\XGetopt.obj $(OUTDIR)\DarunGrim.obj $(OUTDIR)\LogOperation.obj $(OUTDIR)\RegistryUtil.obj
    $(link) $(conflags) -out:$(OUTDIR)\DarunGrim2C.exe $(conlibs) $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(conlibs) $(ZLIB_LIB)\zlib.lib $(SQLITE_DIR_LIB)\sqlite3.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DarunGrim2C.obj $(OUTDIR)\XGetopt.obj $(OUTDIR)\DarunGrim.obj $(OUTDIR)\LogOperation.obj $(OUTDIR)\RegistryUtil.obj

Python\DiffEngine_wrap.cxx: Python\DiffEngine.i
	$(SWIG) -c++ -python Python\DiffEngine.i

$(OUTDIR)\DiffEngine_wrap.obj: Python\DiffEngine_wrap.cxx
    $(cc) $(cflags) $(cvars) $(python_include) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" Python\DiffEngine_wrap.cxx

$(OUTDIR)\_DiffEngine.pyd: $(OUTDIR) $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(ZLIB_LIB)\zlib.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DiffEngine_wrap.obj $(ZLIB_LIB)\zlib.lib $(SQLITE_DIR_LIB)\sqlite3.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DarunGrim.obj $(OUTDIR)\LogOperation.obj $(OUTDIR)\RegistryUtil.obj
    $(link) $(linkdebug) /DEBUG $(dlllflags) \
    -base:0x1C000000 \
    -out:$(OUTDIR)\_DiffEngine.pyd\
    $(python_lflags) \
    $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(ZLIB_LIB)\zlib.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DiffEngine_wrap.obj $(LIBS) $(ZLIB_LIB)\zlib.lib $(SQLITE_DIR_LIB)\sqlite3.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DarunGrim.obj $(OUTDIR)\LogOperation.obj $(OUTDIR)\RegistryUtil.obj

$(OUTDIR)\Test.exe: $(OUTDIR) $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(ZLIB_LIB)\zlib.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\Test.obj $(OUTDIR)\XGetopt.obj $(OUTDIR)\DarunGrim.obj $(OUTDIR)\LogOperation.obj $(OUTDIR)\RegistryUtil.obj
    $(link) $(conflags) -out:$(OUTDIR)\Test.exe $(conlibs) $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(conlibs) $(ZLIB_LIB)\zlib.lib $(SQLITE_DIR_LIB)\sqlite3.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\Test.obj $(OUTDIR)\XGetopt.obj $(OUTDIR)\DarunGrim.obj $(OUTDIR)\LogOperation.obj $(OUTDIR)\RegistryUtil.obj

$(OUTDIR)\Test.obj: $(DIFF_ENGINE)\Test.cpp $(DIFF_ENGINE)\DataStructure.h DiffMachine.h DiffMachine.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\Test.cpp

#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
