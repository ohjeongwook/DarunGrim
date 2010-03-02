# Nmake macros for building Windows 32-Bit apps

!include <win32.mak>

DEBUG_LIB=\mat\Projects\ResearchTools\Debug
IDA_LIB_DIR=..\..\..\..\IdaLib
LIB_DIR=..\..\Lib
ZLIB_DIR=\mat\Bin\zlib
ZLIB_INC=$(ZLIB_DIR)\include
ZLIB_LIB=$(ZLIB_DIR)\lib
ZLIB_WRAPPER_DIR=\mat\Projects\ResearchTools\Algorithms\ZlibWrapper
DIFF_LIB_DIR=\mat\Projects\ResearchTools\Algorithms\Diff
SWIG=C:\mat\bin\swigwin-1.3.36\swig.exe
PYTHON_INCLUDE="c:\python25\include"
PYTHON_LIBS="c:\python25\Libs"

DBWRAPPER_DIR=T:\mat\Projects\ResearchTools\Database
SQLITE_DIR=\mat\Projects\ResearchTools\Database\sqlite-source-3_6_7
SQLITE_DIR_INC=$(SQLITE_DIR)
SQLITE_DIR_LIB=$(SQLITE_DIR)\bin

cflags=$(cflags) -I$(SQLITE_DIR_INC) -I$(DBWRAPPER_DIR) -I$(LIB_DIR) -I$(IDA_LIB_DIR) -I$(DEBUG_LIB) -I$(ZLIB_INC) -I$(ZLIB_WRAPPER_DIR) -I$(DIFF_LIB_DIR) /EHsc /D "_CRT_SECURE_NO_DEPRECATE" /D "USE_DANGEROUS_FUNCTIONS" -DSTANDALONE_SERVER /Zi -Ddprintf=printf
conflags=$(conflags) 
conlibs=$(conlibs) user32.lib
linkdebug=/DEBUG
cflags=$(cflags) -I"$(CFIX_HOME)\include" -DUNIT_TESTING -I.. /Zi /EHsc
dlllflags=$(dlllflags) "$(CFIX_HOME)\\lib\i386\cfix.lib" /DEBUG $(SQLITE_DIR_LIB)\sqlite3.lib 
all: $(OUTDIR) $(OUTDIR)\Test.dll

#----- If OUTDIR does not exist, then create directory
$(OUTDIR) :
    if not exist "$(OUTDIR)/$(NULL)" mkdir $(OUTDIR)

$(OUTDIR)\Test.obj: Test.cpp
    $(cc) $(cflags) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" Test.cpp

$(OUTDIR)\DiffMachine.obj: ..\DiffMachine.cpp
    $(cc) $(cflags) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" ..\DiffMachine.cpp

$(OUTDIR)\IDAClientManager.obj: ..\IDAClientManager.cpp
    $(cc) $(cflags) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" ..\IDAClientManager.cpp

$(OUTDIR)\OneIDAClientManager.obj: ..\OneIDAClientManager.cpp
    $(cc) $(cflags) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" ..\OneIDAClientManager.cpp

$(OUTDIR)\SharedMemory.obj: $(LIB_DIR)\SharedMemory.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SharedMemory.cpp


$(OUTDIR)\SharedSocket.obj: $(LIB_DIR)\SharedSocket.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SharedSocket.cpp


$(OUTDIR)\ProcessUtils.obj: $(LIB_DIR)\ProcessUtils.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\ProcessUtils.cpp

$(OUTDIR)\SocketOperation.obj: $(LIB_DIR)\SocketOperation.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SocketOperation.cpp

$(OUTDIR)\Diff.obj: $(DIFF_LIB_DIR)\Diff.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_LIB_DIR)\Diff.cpp

$(OUTDIR)\Varray.obj: $(DIFF_LIB_DIR)\Varray.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_LIB_DIR)\Varray.cpp

$(OUTDIR)\DBWrapper.obj: $(DBWRAPPER_DIR)\DBWrapper.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DBWRAPPER_DIR)\DBWrapper.cpp

$(OUTDIR)\DatabaseWriter.obj: $(LIB_DIR)\DataBaseWriter.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\DataBaseWriter.cpp

# Update the dynamic link library
$(OUTDIR)\Test.dll: $(OUTDIR)\Test.obj Test.def $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DBWrapper.obj $(OUTDIR)\DatabaseWriter.obj
    $(link) $(dlllflags)     \
    -base:0x1C000000  \
    -out:$(OUTDIR)\Test.dll   \
    $(OUTDIR)\Test.obj $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DBWrapper.obj $(OUTDIR)\DatabaseWriter.obj ws2_32.lib $(ZLIB_LIB)\zlib.lib user32.lib
    
#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
