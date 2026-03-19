# RenameDevice-Intune

A lightweight Microsoft Intune Win32 app that silently renames Windows devices using their BIOS serial number, following the naming convention `ShTech<SerialNumber>`.

The rename is staged silently during the Intune install and takes effect on the user's next natural restart or shutdown — no forced reboot, no user interruption.

---

## Naming Convention

| Prefix | Source | Example |
|--------|--------|---------|
| `ShTech` | Fixed prefix | `ShTechXYZ1234567` |

- Special characters are stripped from the serial number
- The final name is capped at 15 characters (Windows limit)

---

## Files

| File | Purpose |
|------|---------|
| `Install.ps1` | Renames the device and drops a detection tag file |
| `Detect.ps1` | Tells Intune whether the rename has been applied or staged |

---

## How It Works

1. Intune deploys the Win32 app silently as SYSTEM
2. `Install.ps1` reads the device serial number via `Get-CimInstance`
3. The device is renamed using `Rename-Computer` (no restart forced)
4. A tag file is written to `C:\ProgramData\Microsoft\RenameDevice\Rename.tag`
5. The script exits `0` — Intune shows no reboot prompt
6. On the user's next natural restart, the new name takes effect

---

## Intune Configuration

### App Type
Win32 app (`.intunewin`)

### Commands
| | Command |
|---|---|
| **Install** | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Install.ps1"` |
| **Uninstall** | `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Remove-Item -Path '$env:ProgramData\Microsoft\RenameDevice\Rename.tag' -Force -ErrorAction SilentlyContinue; exit 0"` |

### App Settings
| Setting | Value |
|---------|-------|
| Install behavior | System |
| Device restart behavior | No specific action |
| End user notifications | Hide all toast notifications |

### Detection Rule
| Setting | Value |
|---------|-------|
| Rules format | Use a custom detection script |
| Script file | `Detect.ps1` |
| Run script as 32-bit | No |
| Enforce signature check | No |

---

## Requirements

- Windows 10 / 11
- Microsoft Intune (Win32 app deployment)
- Device must have a readable BIOS serial number

---

## Notes

- The script automatically relaunches as a 64-bit process if Intune runs it as 32-bit
- If the serial number contains invalid characters, they are stripped automatically
- If the generated name exceeds 15 characters, it is truncated to fit the Windows limit
- The detection script reports success if the name is already correct **or** if the rename is pending reboot
