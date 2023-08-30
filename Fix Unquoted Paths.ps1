Function UnQuotedPathsFix
{        

    $FuncName = "UnQuotedPathsFix"
    $funcDescription = "Fix Upqupted paths - Identify any unquoted path vulnerability for either .exe or .sys and double quote image path is missing"        

    Start-Transcript -Path "$($env:USERPROFILE)\UnQuotedFix.log" 
       
    Write-Host " "
    Write-Host "<#-----------------------------" -ForegroundColor Green
    Write-Host "<#-----------------------------" -ForegroundColor Green
    Write-Host " "
    Write-Host "Function Name: " -ForegroundColor Green -NoNewline
    write-host "$FuncName" -ForegroundColor Yellow
    Write-Host " "
    Write-Host "Description: " -ForegroundColor Green -NoNewline
    Write-Host "$funcDescription" -ForegroundColor Green 
    Write-Host "-----------------------------#>" -ForegroundColor Green
    Write-Host "-----------------------------#>" -ForegroundColor Green
    Write-Host " "

    #ID Unquoted paths
    $vulnSvc = Get-CimInstance win32_service | foreach{$_} | 
    where {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | 
    where {-not $_.pathname.startswith("`"")} | 
    where {($_.pathname.substring(0, $_.pathname.indexof(".sys") + 4 )) -match ".* .*" `
    -or ($_.pathname.substring(0, $_.pathname.indexof(".exe") + 4 )) -match ".* .*" }

    #Fix Unquoted paths
    foreach ($unQSvc in $vulnSvc)
        {
            $svc = $unQSvc.name
            write-host "Service is vulnerable - $svc"
            $SvcReg = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\$svc
            write-host "Path is HKLM:\SYSTEM\CurrentControlSet\Services\$svc"

            if ($SvcReg.imagePath -like "*.exe *")
                {
                    $SvcRegSp =  $SvcReg.imagePath -split ".exe"
                    $SvcRegSp0 = $SvcRegSp[0]
                    $SvcRegSp1 = $SvcRegSp[1]
                    $image = "`"$SvcRegSp0" + ".exe`""+  " " + $SvcRegSp1
                    Write-Host "Setting $image"
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name ImagePath -Value $image

                    $SvcRegCheck = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\$svc
                    if ($image -eq $SvcRegCheck.ImagePath){Write-host "$svc vulnerability has been resolved"}
                    else{Write-Host "Warning further action for $svc is required"}
                    Write-Host " " 
 
                }
            if ($SvcReg.imagePath -like "*.sys *")
                {
                    $SvcRegSp =  $SvcReg.imagePath -split ".sys"
                    $SvcRegSp0 = $SvcRegSp[0]
                    $SvcRegSp1 = $SvcRegSp[1]
                    $image = "`"$SvcRegSp0" + ".sys`""+   " $SvcRegSp1"
                    Write-Host "Setting $image"
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name ImagePath -Value $image

                    $SvcRegCheck = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\$svc
                    if ($image -eq $SvcRegCheck.ImagePath){Write-host "$svc vulnerability has been resolved"}
                    else{Write-Host "Warning further action for $svc is required"}
                    Write-Host " " 
  
                }
            if ($SvcReg.imagePath -like "*.exe") 
                {
                    $image = $SvcReg.ImagePath
                    Write-Host "Setting $image"
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name ImagePath -Value "`"$image`""

                    $SvcRegCheck = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\$svc
                    if ($image -eq $SvcRegCheck.ImagePath){Write-host "$svc vulnerability has been resolved"}
                    else{Write-Host "Warning further action for $svc is required"}
                    Write-Host " " 
 
                }
        }
    Stop-Transcript
    Invoke-Item "$($env:USERPROFILE)\UnQuotedFix.log" 

}
UnQuotedPathsFix
  
