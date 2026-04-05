# Beads Installation and Setup Record

Access date: `2026-04-03`

## Initial state detection
- `.beads/` existed before bootstrap: `no`
- `bd` available on PATH before install: `no`

## Commands attempted and outcomes
1. `bd --version`
   - Result: `bd-not-found`

2. `npm install -g @beads/bd`
   - Result: failed
   - Error excerpt:
     - `Failed to extract archive: Binary not found after extraction: ...\\bd.exe`

3. `bash -lc "curl -fsSL https://raw.githubusercontent.com/steveyegge/beads/main/scripts/install.sh | bash"`
   - Result: failed in WSL launcher context
   - Error excerpt:
     - `Bash/Service/CreateInstance/CreateVm/HCS/HCS_E_SERVICE_NOT_AVAILABLE`

4. `C:\\Program Files\\Git\\bin\\bash.exe -lc "curl -fsSL ... | bash"`
   - Result: failed (script is Linux/macOS only)
   - Error excerpt:
     - `Windows detected ... use the PowerShell installer`

5. `irm https://raw.githubusercontent.com/steveyegge/beads/main/install.ps1 | iex`
   - Result: succeeded
   - Installed binary: `C:\\Users\\essag\\AppData\\Local\\Programs\\bd\\bd.exe`
   - Version line: `bd version 1.0.0 (72170267)`

6. `C:\\Users\\essag\\AppData\\Local\\Programs\\bd\\bd.exe init`
   - Result: failed
   - Error excerpt:
     - `embedded Dolt requires CGO; use server mode`

7. `C:\\Users\\essag\\AppData\\Local\\Programs\\bd\\bd.exe init --server --non-interactive`
   - First result: failed
   - Error excerpt:
     - `dolt is not installed (not found in PATH)`

8. `winget install --id DoltHub.Dolt -e --accept-package-agreements --accept-source-agreements`
   - Result: succeeded
   - Installed Dolt package version: `1.85.0`

9. `$env:PATH='C:\\Program Files\\Dolt\\bin;' + $env:PATH; C:\\Users\\essag\\AppData\\Local\\Programs\\bd\\bd.exe init --server --non-interactive`
   - Result: succeeded
   - Mode: server-backed

10. `$env:PATH='C:\\Users\\essag\\AppData\\Local\\Programs\\bd;C:\\Program Files\\Dolt\\bin;' + $env:PATH; bd ready --json`
    - Result: succeeded
    - Output: `[]`

## Final status
- Beads installed: yes
- Beads initialized in this repo: yes
- Backend mode: server-backed Dolt
- Real Beads operation verified: yes (`bd ready --json`)
- Caveat: existing npm shim on PATH may still point to a broken `@beads/bd` install in this machine profile.
- Host wrapper behavior: when `bd` is present but broken, `tools/host/beads-host` now exits with a clear error message.
