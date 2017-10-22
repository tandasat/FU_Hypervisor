@echo off
del *.sdf
del *.VC.db
del /s *.aps
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q x64
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q FU_Hypervisor\x64
rmdir /s /q FU_Hypervisor\Debug
rmdir /s /q FU_Hypervisor\Release
cd HyperPlatform
clean.bat
