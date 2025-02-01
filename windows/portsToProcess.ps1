Write-Host "TCP Connections Listening" -ForegroundColor Green
Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess, 
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess).Name}}, 
    @{Name='Services';Expression={
        $processId = $_.OwningProcess
        $procName = (Get-Process -Id $processId).Name
        if ($procName -eq 'svchost') {
            (Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq $processId } | Select-Object -ExpandProperty Name) -join ', '
        } else {
            $null
        }
    }} | Format-Table -AutoSize -Wrap

Write-Host "TCP Connections Established" -ForegroundColor Green
Get-NetTCPConnection -State Established | Select-Object LocalPort, OwningProcess, 
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess).Name}}, 
    @{Name='Services';Expression={
        $processId = $_.OwningProcess
        $procName = (Get-Process -Id $processId).Name
        if ($procName -eq 'svchost') {
            (Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq $processId } | Select-Object -ExpandProperty Name) -join ', '
        } else {
            $null
        }
    }} | Format-Table -AutoSize -Wrap

Write-Host "UDP Endpoints" -ForegroundColor Green
Get-NetUDPEndpoint | Select-Object LocalPort, OwningProcess, 
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess).Name}}, 
    @{Name='Services';Expression={
        $processId = $_.OwningProcess
        $procName = (Get-Process -Id $processId).Name
        if ($procName -eq 'svchost') {
            (Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq $processId } | Select-Object -ExpandProperty Name) -join ', '
        } else {
            $null
        }
    }} | Format-Table -AutoSize -Wrap

Write-Host "TCP Connections Listening" -ForegroundColor Green
Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess, 
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess).Name}}, 
    @{Name='Services';Expression={
        $processId = $_.OwningProcess
        $procName = (Get-Process -Id $processId).Name
        if ($procName -eq 'svchost') {
            (Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq $processId } | Select-Object -ExpandProperty Name) -join ', '
        } else {
            $null
        }
    }} | Format-Table -AutoSize -Wrap

Write-Host "TCP Connections Established" -ForegroundColor Green
Get-NetTCPConnection -State Established | Select-Object LocalPort, OwningProcess, 
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess).Name}}, 
    @{Name='Services';Expression={
        $processId = $_.OwningProcess
        $procName = (Get-Process -Id $processId).Name
        if ($procName -eq 'svchost') {
            (Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq $processId } | Select-Object -ExpandProperty Name) -join ', '
        } else {
            $null
        }
    }} | Format-Table -AutoSize -Wrap

Write-Host "UDP Endpoints" -ForegroundColor Green
Get-NetUDPEndpoint | Select-Object LocalPort, OwningProcess, 
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess).Name}}, 
    @{Name='Services';Expression={
        $processId = $_.OwningProcess
        $procName = (Get-Process -Id $processId).Name
        if ($procName -eq 'svchost') {
            (Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq $processId } | Select-Object -ExpandProperty Name) -join ', '
        } else {
            $null
        }
    }} | Format-Table -AutoSize -Wrap

Read-Host -Prompt "Press Enter to exit"
