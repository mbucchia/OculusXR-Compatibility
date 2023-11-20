@echo off
pushd %~dp0
wpr -start VirtualDesktopOculusCompat.wprp -filemode

echo Reproduce your issue now, then
pause

wpr -stop VD-OculusXR.etl
popd
