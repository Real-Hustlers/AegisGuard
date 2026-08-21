AegisGuard Collector Inno Setup build

1. On the Windows development PC, make sure the current packaged Collector exists at:
   C:\Users\saran\makethon\dist\AegisGuardCollector\
   containing AegisGuardCollector.exe and _internal\.

2. Put this installer folder at:
   C:\Users\saran\makethon\installer\

   with:
   - AegisGuardCollector.iss
   - BUILD-INSTALLER.bat

3. Install Inno Setup 6.

4. Run BUILD-INSTALLER.bat.

5. The output installer will be created under:
   C:\Users\saran\makethon\installer\output\

6. The installer asks for:
   - Analyzer URL
   - Historical collection hours
   - Maximum historical events
   - Start at Windows startup (default: enabled)

7. It writes an external config.json next to the installed EXE and creates a Scheduled Task named:
   AegisGuard Collector

8. The Collector is started immediately after installation.

Important prerequisites:
- The built Collector must use a config_loader.py that reads config.json from the EXE directory when frozen.
- Do not ship secrets or the SQLite database in the Collector installer.
- Test the installer on a second Windows laptop before publishing it on GitHub Releases.
