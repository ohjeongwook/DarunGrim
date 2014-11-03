# Nmake macros for building Windows 32-Bit apps

!include <Win32.Mak>
DARUNGRIM2_ROOT=..\..\DarunGrim2
!include "$(DARUNGRIM2_ROOT)\Paths.Mak"
PLUGIN_DIR=$(DARUNGRIM2_ROOT)\Plugin
DIFF_ENGINE=$(DARUNGRIM2_ROOT)\DiffEngine
LIB_DIR=$(DARUNGRIM2_ROOT)\Lib

cflags=$(cflags) -I$(SQLITE_DIR_INC) 
cflags=$(cflags) -I$(DEBUG_LIB_DIR) 
cflags=$(cflags) -I$(IDA_LIB_DIR) 
cflags=$(cflags) -I$(GRAPHVIZ_INTERFACE) 
cflags=$(cflags) -D_CRT_SECURE_NO_WARNINGS 
cflags=$(cflags) -I$(GRAPHVIZ_INTERFACE) 
cflags=$(cflags) -I$(DIFF_LIB_DIR) 
cflags=$(cflags) -I$(GRAPHVIZ_INCLUDE) 
cflags=$(cflags) -I$(ZLIB_INC) 
cflags=$(cflags) -I$(ZLIB_WRAPPER_DIR) 
cflags=$(cflags) -I$(DBWRAPPER_DIR) 
cflags=$(cflags) -I$(PLUGIN_DIR)
cflags=$(cflags) -I$(LOGGER_DIR)
cflags=$(cflags) /DEBUG /Zi /EHsc 
cflags=$(cflags) -Ddprintf=PrintToDbg 

graphviz_flags=/DEBUG /LIBPATH:$(GRAPHVIZ_LIB)
graphviz_libs=cdt.lib graph.lib gvc.lib /NODEFAULTLIB:LIBC /NODEFAULTLIB:LIBCD 
cflags=-I$(WTL_DIR)\include $(cflags) -I$(LIB_DIR) -I$(DIFF_ENGINE) /EHsc -I$(GRAPHVIZ_INTERFACE) -I$(REGISTRY_API_DIR)

guiflags=$(guiflags) odbc32.lib odbccp32.lib comctl32.lib

all: $(OUTDIR) $(OUTDIR)\DarunGrim2.exe

#----- If OUTDIR does not exist, then create directory
$(OUTDIR) :
    if not exist "$(OUTDIR)/$(NULL)" mkdir $(OUTDIR)

$(OUTDIR)\FlowGrapher.obj: $(GRAPHVIZ_INTERFACE)\FlowGrapher.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(GRAPHVIZ_INTERFACE)\FlowGrapher.cpp

$(OUTDIR)\Main.res: Main.rc 
    rc -r /fo $(OUTDIR)\Main.res -I$(WTL_DIR)\include Main.rc

$(OUTDIR)\Main.obj: Main.cpp MainFrame.h SelectFilesDlg.h LogViewerDlg.h stdafx.h $(GRAPHVIZ_INTERFACE)\CGraphVizWindow.h $(OUTDIR)\Main.res 
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" Main.cpp    

$(OUTDIR)\DarunGrim2.exe: $(OUTDIR)\Main.obj $(OUTDIR)\Main.res $(OUTDIR)\FlowGrapher.obj $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(ZLIB_LIB)\zlib.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\RegistryUtil.obj $(OUTDIR)\DarunGrim.obj $(OUTDIR)\LogOperation.obj
    $(link) $(guiflags) $(graphviz_flags) -out:$(OUTDIR)\DarunGrim2.exe $(OUTDIR)\Main.obj $(OUTDIR)\FlowGrapher.obj $(OUTDIR)\Main.res $(guilibs) $(graphviz_libs) $(OUTDIR)\IDAClientManager.obj $(OUTDIR)\OneIDAClientManager.obj $(OUTDIR)\DiffMachine.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(conlibs) $(ZLIB_LIB)\zlib.lib $(SQLITE_DIR_LIB)\sqlite3.lib $(OUTDIR)\dprintf.obj $(OUTDIR)\Diff.obj $(OUTDIR)\Varray.obj $(OUTDIR)\DataBaseWriter.obj $(OUTDIR)\RegistryUtil.obj $(OUTDIR)\DarunGrim.obj $(OUTDIR)\LogOperation.obj

$(OUTDIR)\DarunGrim.obj: $(DIFF_ENGINE)\DarunGrim.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\DarunGrim.cpp

$(OUTDIR)\IDAClientManager.obj: $(DIFF_ENGINE)\IDAClientManager.cpp $(DIFF_ENGINE)\DataStructure.h
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DIFF_ENGINE)\IDAClientManager.cpp

$(OUTDIR)\dprintf.obj: $(DEBUG_LIB_DIR)\dprintf.cpp 
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(DEBUG_LIB_DIR)\dprintf.cpp

$(OUTDIR)\LogOperation.obj: $(LOGGER_DIR)\LogOperation.cpp 
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LOGGER_DIR)\LogOperation.cpp
    
$(OUTDIR)\RegistryUtil.obj: $(REGISTRY_API_DIR)\RegistryUtil.cpp 
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(REGISTRY_API_DIR)\RegistryUtil.cpp    

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

#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
