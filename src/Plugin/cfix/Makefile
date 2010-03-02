# Nmake macros for building Windows 32-Bit apps

!include <win32.mak>

cflags=$(cflags) -I"$(CFIX_HOME)\include" -DUNIT_TESTING /MT -I.. /Zi
dlllflags=$(dlllflags) "$(CFIX_HOME)\\lib\i386\cfix.lib" /DEBUG
all: $(OUTDIR) $(OUTDIR)\Test.dll

#----- If OUTDIR does not exist, then create directory
$(OUTDIR) :
    if not exist "$(OUTDIR)/$(NULL)" mkdir $(OUTDIR)

$(OUTDIR)\Test.obj: Test.cpp
    $(cc) $(cflags) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" Test.cpp

$(OUTDIR)\DarunGrim2.obj: ..\DarunGrim2.cpp
    $(cc) $(cflags) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" ..\DarunGrim2.cpp

# Update the dynamic link library
$(OUTDIR)\Test.dll: $(OUTDIR)\Test.obj Test.def $(OUTDIR)\DarunGrim2.obj
    $(link) $(dlllflags)     \
    -base:0x1C000000  \
    -out:$(OUTDIR)\Test.dll   \
    $(OUTDIR)\Test.obj $(OUTDIR)\DarunGrim2.obj
    
#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
