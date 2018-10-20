@echo off

setlocal

rem Run pinadx-vsextension.msi
echo Installing PinAdx...
start /wait extras\pinadx-vsplugin\pinadx-vsextension-3.7.97619-g0d0c92f4f.msi

rem x64 cpu
if "AMD64" == "%PROCESSOR_ARCHITECTURE%" (
  rem If VS2017 is installed then integrate PinUi
  if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2017" (
    echo Integrating PinUi to VS2017...
    start /wait extras\pinadx-vsplugin\pin-vs-plugin_2017.vsix
  )
  goto end
)

rem x86 cpu
if "x86" == "%PROCESSOR_ARCHITECTURE%" (
  rem If VS2017 is installed then integrate PinUi
  if exist "%ProgramFiles%\Microsoft Visual Studio\2017" (
    echo Integrating PinUi to VS2017...
    start /wait extras\pinadx-vsplugin\pin-vs-plugin_2017.vsix
  )
  goto end
)

:end
endlocal
