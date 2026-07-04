"""
TAALA-2KEN — Auto-Start Task Scheduler Provisioner.

Generates a Windows Task Scheduler XML profile to load the USB Auth Guard
windowless tray monitor automatically upon user logon with elevated privileges.
"""

import sys
from pathlib import Path
from taala2ken import constants as C

XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-07-04T12:00:00</Date>
    <Author>TAALA-2KEN</Author>
    <Description>Auto-start daemon for USB Authentication Guard monitoring.</Description>
    <URI>\\Taala2KenAuthGuard</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>PYTHON_EXE</Command>
      <Arguments>ARGUMENTS</Arguments>
      <WorkingDirectory>WORKING_DIR</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""

def generate_xml() -> Path:
    python_exe = sys.executable.replace("python.exe", "pythonw.exe")
    script_path = str(C.PROJECT_ROOT / "run.pyw")
    working_dir = str(C.PROJECT_ROOT)

    content = XML_TEMPLATE.replace("PYTHON_EXE", python_exe)
    content = content.replace("ARGUMENTS", f'"{script_path}"')
    content = content.replace("WORKING_DIR", working_dir)

    output_path = C.PROJECT_ROOT / "Taala2KenAutostart.xml"
    with open(output_path, "w", encoding="utf-16") as f:
        f.write(content)

    print(f"\n  ✓ Task Scheduler XML generated: {output_path.name}")
    print("  To register the auto-start task with Windows, run (in Admin PowerShell):")
    print(f'  Register-ScheduledTask -Xml (Get-Content "{output_path.name}" -Raw) -TaskName "Taala2KenAuthGuard"')
    print()
    return output_path

if __name__ == "__main__":
    generate_xml()
