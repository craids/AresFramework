@echo off

    if exist "isfcspoc.obj" del "isfcspoc.obj"
    if exist "isfcspoc.exe" del "isfcspoc.exe"

    \masm32\bin\ml /c /coff "isfcspoc.asm"
    if errorlevel 1 goto errasm

    \masm32\bin\PoLink /SUBSYSTEM:CONSOLE "isfcspoc.obj"
    if errorlevel 1 goto errlink
    dir "isfcspoc.*"
    goto TheEnd

  :errlink
    echo _
    echo Link error
    goto TheEnd

  :errasm
    echo _
    echo Assembly Error
    goto TheEnd
    
  :TheEnd

pause
