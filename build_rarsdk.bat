@echo off
rem build_rarsdk.bat - build rarsdk.dll
setlocal
set VC=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat
set SDK=%~dp0
set OBJ=%SDK%\obj
set OUT=%SDK%\bin
if not exist %OBJ% mkdir %OBJ%
if not exist %OUT% mkdir %OUT%

call "%VC%" x64 >nul 2>&1
if errorlevel 1 (echo FAILED: VS env & exit /b 1)

set DEFS=/DRARSDK_BUILD /DRARDLL /DUNRAR /DSILENT /D_FILE_OFFSET_BITS=64 /D_LARGEFILE_SOURCE /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX
set OPTS=/nologo /O2 /W3 /EHsc /c %DEFS%

rem ---- 1) UnRAR objects ----
cd /d %SDK%\unrar
set SRC=rar strlist strfn pathfn smallfn global file filefn filcreat archive arcread unicode system crypt crc rawread encname resource match timefn rdwrfn consio options errhnd rarvm secpassword rijndael getbits sha1 sha256 blake2s hash extinfo extract volume list find unpack headers threadpool rs16 cmddata ui dll qopen filestr scantree isnt
set FAILED=0
for %%F in (%SRC%) do (
  if not exist %OBJ%\%%F.obj (
    cl %OPTS% /Fo%OBJ%\%%F.obj %%F.cpp >nul 2>&1
    if not exist %OBJ%\%%F.obj (echo [UNRAR] compile FAILED: %%F & set /a FAILED+=1)
  )
)
if %FAILED% GTR 0 goto :showerr

rem ---- 2) writer objects ----
cd /d %SDK%
for %%F in (rs_writer rs_aes rs_rs16 rs_create rs_bridge rs_extra rs_blake) do (
  if not exist %OBJ%\%%F.obj (
    cl %OPTS% /Fo%OBJ%\%%F.obj %%F.cpp >nul 2>&1
    if not exist %OBJ%\%%F.obj (echo [WRITER] compile FAILED: %%F & set /a FAILED+=1)
  )
)
if %FAILED% GTR 0 goto :showerr

rem ---- 3) link ----
link /nologo /DLL /OUT:%OUT%\rarsdk.dll /DEF:%SDK%\rarsdk.def ^
  %OBJ%\rar.obj %OBJ%\strlist.obj %OBJ%\strfn.obj %OBJ%\pathfn.obj %OBJ%\smallfn.obj ^
  %OBJ%\global.obj %OBJ%\file.obj %OBJ%\filefn.obj %OBJ%\filcreat.obj %OBJ%\archive.obj ^
  %OBJ%\arcread.obj %OBJ%\unicode.obj %OBJ%\system.obj %OBJ%\crypt.obj %OBJ%\crc.obj ^
  %OBJ%\rawread.obj %OBJ%\encname.obj %OBJ%\resource.obj %OBJ%\match.obj %OBJ%\timefn.obj ^
  %OBJ%\rdwrfn.obj %OBJ%\consio.obj %OBJ%\options.obj %OBJ%\errhnd.obj %OBJ%\rarvm.obj ^
  %OBJ%\secpassword.obj %OBJ%\rijndael.obj %OBJ%\getbits.obj %OBJ%\sha1.obj %OBJ%\sha256.obj ^
  %OBJ%\blake2s.obj %OBJ%\hash.obj %OBJ%\extinfo.obj %OBJ%\extract.obj %OBJ%\volume.obj ^
  %OBJ%\list.obj %OBJ%\find.obj %OBJ%\unpack.obj %OBJ%\headers.obj %OBJ%\threadpool.obj ^
  %OBJ%\rs16.obj %OBJ%\cmddata.obj %OBJ%\ui.obj %OBJ%\dll.obj %OBJ%\qopen.obj ^
  %OBJ%\rs_writer.obj %OBJ%\rs_aes.obj %OBJ%\rs_rs16.obj %OBJ%\rs_create.obj %OBJ%\rs_bridge.obj %OBJ%\rs_extra.obj %OBJ%\rs_blake.obj %OBJ%\filestr.obj %OBJ%\scantree.obj %OBJ%\isnt.obj ^
  /MACHINE:X64 advapi32.lib user32.lib shell32.lib ole32.lib
if exist %OUT%\rarsdk.dll (echo OK: %OUT%\rarsdk.dll) else (echo LINK FAILED)
exit /b 0
:showerr
echo Compilation errors occurred.
exit /b 1
