# Nmake macros for building Windows 32-Bit apps

!include <Win32.Mak>

PLUGIN_DIR=..\Plugin
DEBUG_LIB=\mat\Projects\ResearchTools\Debug
IDA_LIB_DIR=..\..\..\IDALib
GRAPHVIZ_INTERFACE=.
ZLIB_DIR=\mat\Projects\Lib\zlib
ZLIB_INC=$(ZLIB_DIR)\include
ZLIB_LIB=$(ZLIB_DIR)\lib
DIFF_LIB_DIR=\mat\Projects\ResearchTools\Algorithms\Diff
ZLIB_WRAPPER_DIR=\mat\Projects\ResearchTools\Algorithms\ZlibWrapper

DBWRAPPER_DIR=T:\mat\Projects\ResearchTools\Database
SQLITE_DIR=\mat\Projects\ResearchTools\Database\sqlite-source-3_6_7
SQLITE_DIR_INC=$(SQLITE_DIR)
SQLITE_DIR_LIB=$(SQLITE_DIR)\bin

cflags=$(cflags) -I$(SQLITE_DIR_INC) -I$(DEBUG_LIB) -I$(IDA_LIB_DIR) -I$(GRAPHVIZ_INTERFACE) -D_CRT_SECURE_NO_WARNINGS -I\mat\Projects\ResearchTools\Graphics\GraphVizInterface\Src -I$(DIFF_LIB_DIR) -I"\mat\Projects\Lib\GraphViz\include" -I$(ZLIB_INC) -I$(ZLIB_WRAPPER_DIR) /DEBUG /Zi /EHsc -Ddprintf=PrintToDbg -I$(DBWRAPPER_DIR) -I$(PLUGIN_DIR)

graphviz_flags=/DEBUG /LIBPATH:"\mat\Projects\Lib\GraphViz\lib"
graphviz_libs=cdt.lib graph.lib gvc.lib /NODEFAULTLIB:LIBC /NODEFAULTLIB:LIBCD 

GRAPHVIZ_INTERFACE=\mat\Projects\ResearchTools\Graphics\GraphVizInterface\Src

DIFF_ENGINE=..\DiffEngine
LIB_DIR=..\Lib

cflags=$(cflags) -I$(LIB_DIR) -I$(DIFF_ENGINE) /EHsc -Ic:\WTL80\include -I$(GRAPHVIZ_INTERFACE)
guiflags=$(guiflags) odbc32.lib odbccp32.lib comctl32.lib

all: $(OUTDIR) $(OUTDIR)\DarunGrim2.exe

#----- If OUTDIR does not exist, then create directory
$(OUTDIR) :
    if not exist "$(OUTDIR)/$(NULL)" mkdir $(OUTDIR)

$(OUTDIR)\CGraphVizProcessor.obj: $(GRAPHVIZ_INTERFACE)\CGraphVizProcessor.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(GRAPHVIZ_INTERFACE)\CGraphVizProcessor.cpp

$(OUTDIR)\Main.res: Main.rc Main.h
    rc -r /fo $(OUTDIR)\Main.res -IC:\WTL80\include Main.rc
   
$(OUTDIR)\Main.obj: Main.cpp MainFrame.h Main.h stdafx.h $(GRAPHVIZ_INTERFACE)\CGraphVizWindow.h
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" Main.cpp    

$(OUTDIR)\DarunGrim2.exe: $(OUTDIR)\Main.obj $(OUTDIR)\Main.res $(OUTDIR)\CGraphVizProcessor.obj $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(ZLIB_LIB)\zlib.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DBWrapper.obj
    $(link) $(guiflags) $(graphviz_flags) -out:$(OUTDIR)\DarunGrim2.exe $(OUTDIR)\Main.obj $(OUTDIR)\CGraphVizProcessor.obj $(OUTDIR)\Main.res $(guilibs) $(graphviz_libs) $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(conlibs) $(ZLIB_LIB)\zlib.lib $(SQLITE_DIR_LIB)\sqlite3.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DBWrapper.obj

$(OUTDIR)\IDAClientManager.obj: $(DIFF_ENGINE)\IDAClientManager.cpp $(DIFF_ENGINE)\DataStructure.h
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\IDAClientManager.cpp

$(OUTDIR)\dprintf.obj: $(DEBUG_LIB)\dprintf.cpp 
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DEBUG_LIB)\dprintf.cpp

$(OUTDIR)\OneIDAClientManager.obj: $(DIFF_ENGINE)\OneIDAClientManager.cpp $(DIFF_ENGINE)\DataStructure.h
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\OneIDAClientManager.cpp

$(OUTDIR)\DiffMachine.obj: $(DIFF_ENGINE)\DiffMachine.cpp $(DIFF_ENGINE)\DataStructure.h
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\DiffMachine.cpp

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

$(OUTDIR)\DatabaseWriter.obj: $(LIB_DIR)\DataBaseWriter.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\DataBaseWriter.cpp

$(OUTDIR)\DBWrapper.obj: $(DBWRAPPER_DIR)\DBWrapper.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DBWRAPPER_DIR)\DBWrapper.cpp

#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
