# Nmake macros for building Windows 32-Bit apps

!include <Win32.Mak>

cflags=$(cflags) /EHsc /Zi -D_CRT_SECURE_NO_WARNINGS 
conflags=$(conflags) /DEBUG
all: $(OUTDIR) $(OUTDIR)\Clicker.exe

#----- If OUTDIR does not exist, then create directory
$(OUTDIR) :
    if not exist "$(OUTDIR)/$(NULL)" mkdir $(OUTDIR)

$(OUTDIR)\Clicker.obj: Clicker.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" Clicker.cpp

$(OUTDIR)\Implementation.obj: Implementation.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" Implementation.cpp

$(OUTDIR)\Clicker.exe: $(OUTDIR)\Clicker.obj $(OUTDIR)\Implementation.obj
    $(link) $(conflags) -out:$(OUTDIR)\Clicker.exe $(OUTDIR)\Clicker.obj $(OUTDIR)\Implementation.obj $(conlibs) user32.lib

#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
