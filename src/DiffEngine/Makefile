# Nmake macros for building Windows 32-Bit apps

!include <Win32.Mak>
!include "..\Paths.Mak"

cflags=$(cflags) -I$(SQLITE_DIR_INC) -I$(DEBUG_LIB_DIR) -I$(IDA_LIB_DIR) -I$(GRAPHVIZ_INTERFACE) -D_CRT_SECURE_NO_WARNINGS -I\mat\Projects\ResearchTools\Graphics\GraphVizInterface\Src -I$(DIFF_LIB_DIR) -I"\mat\Projects\Lib\GraphViz\include" -I$(ZLIB_INC) -I$(ZLIB_WRAPPER_DIR) /DEBUG /Zi /EHsc -Ddprintf=PrintToStdOutWithTime -I$(DBWRAPPER_DIR) -I$(LIB_DIR) -I$(XGETOPT_DIR)
conlibs=$(conlibs) user32.lib

graphviz_flags=/DEBUG /LIBPATH:$(GRAPHVIZ_LIB_DIR)
graphviz_libs=cdt.lib graph.lib gvc.lib /NODEFAULTLIB:LIBC /NODEFAULTLIB:LIBCD 

DIFF_ENGINE=..\DiffEngine
LIB_DIR=..\Lib

cflags=$(cflags) -I$(LIB_DIR) -I$(DIFF_ENGINE) /EHsc -Ic:\WTL\include -I$(GRAPHVIZ_INTERFACE)
conflags=$(conflags) odbc32.lib odbccp32.lib comctl32.lib

all: $(OUTDIR) $(OUTDIR)\DarunGrim2C.exe

#----- If OUTDIR does not exist, then create directory
$(OUTDIR) :
    if not exist "$(OUTDIR)/$(NULL)" mkdir $(OUTDIR)

$(OUTDIR)\CGraphVizProcessor.obj: $(GRAPHVIZ_INTERFACE)\CGraphVizProcessor.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(GRAPHVIZ_INTERFACE)\CGraphVizProcessor.cpp

$(OUTDIR)\DarunGrim2C.exe: $(OUTDIR)\CGraphVizProcessor.obj $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(ZLIB_LIB)\zlib.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DarunGrim2C.obj $(OUTDIR)\XGetopt.obj
    $(link) $(conflags) $(graphviz_flags) -out:$(OUTDIR)\DarunGrim2C.exe $(OUTDIR)\CGraphVizProcessor.obj $(conlibs) $(graphviz_libs) $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(conlibs) $(ZLIB_LIB)\zlib.lib $(SQLITE_DIR_LIB)\sqlite3.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\DarunGrim2C.obj $(OUTDIR)\XGetopt.obj

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

$(OUTDIR)\Diff.obj: $(DIFF_LIB_DIR)\Diff.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_LIB_DIR)\Diff.cpp

$(OUTDIR)\Varray.obj: $(DIFF_LIB_DIR)\Varray.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_LIB_DIR)\Varray.cpp

$(OUTDIR)\DatabaseWriter.obj: $(LIB_DIR)\DataBaseWriter.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\DataBaseWriter.cpp

$(OUTDIR)\XGetopt.obj: $(XGETOPT_DIR)\XGetopt.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(XGETOPT_DIR)\XGetopt.cpp

$(OUTDIR)\DarunGrim2C.obj: $(DIFF_ENGINE)\DarunGrim2C.cpp $(DIFF_ENGINE)\DataStructure.h DiffMachine.h DiffMachine.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\DarunGrim2C.cpp

#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
