#define MyAppName "BDFR Sentinel"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "BDFR"
#define MyAppExeName "bdfr-sentinel-gui.exe"
#define MyServiceExe "bdfr-sentinel-service.exe"

[Setup]
AppId={{91F8715A-71D5-4D49-90A4-7D83F2D7B2D4}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\BDFR Sentinel
DefaultGroupName=BDFR Sentinel
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=BDFR-Sentinel-Setup-x64
SetupIconFile=..\assets\sentinel.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=BDFR Sentinel
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
MinVersion=10.0.17763
VersionInfoCompany=BDFR
VersionInfoDescription=BDFR Sentinel Endpoint Security Setup
VersionInfoProductName=BDFR Sentinel

[Files]
Source: "..\target\release\bdfr-sentinel-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\bdfr-sentinel-service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\bdfr-sentinel.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Definitions\*"; DestDir: "{commonappdata}\BDFR\Sentinel\Definitions"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "..\themes\*.json"; DestDir: "{app}\themes"; Flags: ignoreversion createallsubdirs skipifsourcedoesntexist
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\scripts\Uninstall-Protection.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\scripts\Build-Minifilter.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\drivers\minifilter\*"; DestDir: "{app}\drivers\minifilter"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Dirs]
Name: "{commonappdata}\BDFR\Sentinel"
Name: "{commonappdata}\BDFR\Sentinel\Definitions"
Name: "{commonappdata}\BDFR\Sentinel\Quarantine"

[Icons]
Name: "{autoprograms}\BDFR Sentinel"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\BDFR Sentinel"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Run]
Filename: "{app}\{#MyServiceExe}"; Parameters: "install"; StatusMsg: "Installing BDFR Sentinel protection service..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyServiceExe}"; Parameters: "start"; StatusMsg: "Starting BDFR Sentinel protection service..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Description: "Launch BDFR Sentinel"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#MyServiceExe}"; Parameters: "stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopSentinelService"
Filename: "{app}\{#MyServiceExe}"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveSentinelService"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  ExistingService: String;
begin
  Result := '';
  ExistingService := ExpandConstant('{app}\{#MyServiceExe}');

  if FileExists(ExistingService) then
  begin
    Exec(ExistingService, 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(750);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    Exec('icacls.exe',
      '"' + ExpandConstant('{app}') + '" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    Exec('icacls.exe',
      '"' + ExpandConstant('{commonappdata}\BDFR\Sentinel\Quarantine') + '" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
