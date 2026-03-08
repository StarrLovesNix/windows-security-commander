; installer.iss - Inno Setup script for Security Commander
;
; Compile with Inno Setup 6: ISCC.exe build\installer.iss
; (build.py runs this automatically if Inno Setup is installed)
;
; Output: dist\SecurityCommander-Setup.exe

#define AppName      "Security Commander"
#define AppVersion   "1.0.0"
#define AppPublisher "Security Commander"
#define AppExeName   "SecurityCommander.exe"
#define AppURL       "https://github.com/your-repo/windows-security-commander"

[Setup]
AppId={{A8B3C2D1-E4F5-6789-ABCD-EF0123456789}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
OutputDir=..\dist
OutputBaseFilename=SecurityCommander-Setup
SetupIconFile=..\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=Windows Security Monitor

; Run silently in background by default (no console window)
; pythonw.exe is used so the GUI launches without a black terminal

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "Create a desktop shortcut";        GroupDescription: "Shortcuts:"; Flags: checkedonce
Name: "startmenuicon"; Description: "Create a Start Menu shortcut";     GroupDescription: "Shortcuts:"; Flags: checkedonce
Name: "startatboot";   Description: "Start Security Commander at login"; GroupDescription: "Startup:";   Flags: unchecked

[Files]
; Main application (PyInstaller output folder)
Source: "..\dist\SecurityCommander\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Default config (only if user doesn't already have one)
Source: "..\config.json.example"; DestDir: "{app}"; DestName: "config.json"; Flags: onlyifdoesntexist

[Icons]
; Desktop shortcut
Name: "{autodesktop}\{#AppName}"; \
      Filename: "{app}\{#AppExeName}"; \
      IconFilename: "{app}\{#AppExeName}"; \
      Comment: "Real-time Windows security monitor"; \
      Tasks: desktopicon

; Start Menu
Name: "{group}\{#AppName}"; \
      Filename: "{app}\{#AppExeName}"; \
      IconFilename: "{app}\{#AppExeName}"; \
      Comment: "Real-time Windows security monitor"; \
      Tasks: startmenuicon

Name: "{group}\Uninstall {#AppName}"; \
      Filename: "{uninstallexe}"; \
      Tasks: startmenuicon

[Registry]
; Optional: start at login (Run key)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
     ValueType: string; ValueName: "{#AppName}"; \
     ValueData: """{app}\{#AppExeName}"""; \
     Flags: uninsdeletevalue; Tasks: startatboot

[Run]
; Launch after install
Filename: "{app}\{#AppExeName}"; \
          Description: "Launch {#AppName}"; \
          Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up generated data on uninstall (optional — user data kept)
Type: filesandordirs; Name: "{app}\__pycache__"

[Code]
// Show a friendly message if the user is not an admin
procedure InitializeWizard();
begin
  // Nothing needed — Inno Setup handles UAC elevation via PrivilegesRequired=admin
end;
