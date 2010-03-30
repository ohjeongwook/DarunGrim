mkdir Source\ExtLib
copy \mat\Projects\ResearchTools\Database\DBWrapper.h Source\ExtLib
copy \mat\Projects\ResearchTools\Debug\dprintf.* Source\ExtLib
copy \mat\Projects\ResearchTools\Algorithms\Diff\Diff.* Source\ExtLib
copy \mat\Projects\ResearchTools\Algorithms\Diff\Varray.* Source\ExtLib
copy \mat\Projects\ResearchTools\Graphics\GraphVizInterface\Src\*.h Source\ExtLib
copy \mat\Projects\ResearchTools\Graphics\GraphVizInterface\Src\*.cpp Source\ExtLib
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\IDALib\IDAIncludes.h Source\ExtLib
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\IDALib\IDAAnalysis.h Source\ExtLib
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\IDALib\IDAAnalysis.cpp Source\ExtLib
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\IDALib\IDAAnalysisCommon.* Source\ExtLib
copy \mat\Projects\ResearchTools\Console\xGetOpt\XGetopt.* Source\ExtLib
copy \mat\Projects\ResearchTools\Algorithms\ZlibWrapper\ZlibWrapper.* Source\ExtLib
copy \mat\Projects\ResearchTools\Registry\RegistryAPI\RegistryUtil.* Source\ExtLib

mkdir Source\DiffEngine
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\DiffEngine\*.h Source\DiffEngine
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\DiffEngine\*.cpp Source\DiffEngine
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\DiffEngine\Makefile Source\DiffEngine
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\DiffEngine\inst.bat Source\DiffEngine

mkdir Source\UI
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\UI\*.h Source\UI
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\UI\*.cpp Source\UI
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\UI\Makefile Source\UI
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\UI\inst.bat Source\UI
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\UI\*.rc Source\UI
xcopy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\UI\res Source\UI\res\
xcopy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\UI\RC Source\UI\RC\

mkdir Source\Plugin
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Plugin\*.h Source\Plugin
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Plugin\*.cpp Source\Plugin
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Plugin\Makefile Source\Plugin
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Plugin\inst.bat Source\Plugin

mkdir Source\Lib
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Lib\*.h Source\Lib
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Lib\*.cpp Source\Lib
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Lib\Makefile Source\Lib
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Lib\inst.bat Source\Lib

mkdir Source\Bin
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Bin\*.dll Source\Bin
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Bin\*.exe Source\Bin
copy \mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Bin\*.plw Source\Bin