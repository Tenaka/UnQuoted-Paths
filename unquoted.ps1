Function UnQuoted
    {
    <#
    .Synopsis
    Checks for unquoted path vulnerbilities and updates the registry paths by inserting the required double quotes.
   
    .DESCRIPTION
   
    .EXAMPLE
    
    .VERSION
    210617.01 - Created
    #>     
            $secure10 = "C:\Secure10"
            $OutFunc = "UnQuoted" 
                
            $tpSec10 = Test-Path "C:\Secure10\output\$OutFunc\"
        if ($tpSec10 -eq $false)
            {
            New-Item -Path "C:\Secure10\output\$OutFunc\" -ItemType Directory -Force
            }
            $lpath = "C:\Secure10\output\$OutFunc\" + "$OutFunc.log"

 
        #Unquoted paths
        $vulnSvc = gwmi win32_service | foreach{$_} | 
            where {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | 
            where {-not $_.pathname.startswith("`"")} | 
            where {($_.pathname.substring(0, $_.pathname.indexof(".exe") + 4 )) -match ".* .*" }

            foreach ($unQSvc in $vulnSvc)
                {
                $svc = $unQSvc.name
                $SvcReg = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\$svc
            
                    if ($SvcReg.imagePath -like "*.exe *")
                    {
                        $SvcRegSp =  $SvcReg.imagePath -split ".exe"
                        $SvcRegSp0 = $SvcRegSp[0]
                        $SvcRegSp1 = $SvcRegSp[1]
                        $image = "`"$SvcRegSp0" + ".exe`""+  " " + $SvcRegSp1
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name ImagePath -Value $image
                        $SvcReg |Select-Object PSChildName  | out-file $lpath -Append
                        $SvcReg |Select-Object ImagePath  | out-file $lpath -Append
                    }
                    if ($SvcReg.imagePath -like "*.sys *")
                    {
                        $SvcRegSp =  $SvcReg.imagePath -split ".sys"
                        $SvcRegSp0 = $SvcRegSp[0]
                        $SvcRegSp1 = $SvcRegSp[1]
                        $image = "`"$SvcRegSp0" + ".sys`""+   " $SvcRegSp1"
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name ImagePath -Value $image
                        $SvcReg |Select-Object PSChildName  | out-file $lpath -Append
                        $SvcReg |Select-Object ImagePath  | out-file $lpath -Append
                    }
                    if ($SvcReg.imagePath -like "*.exe") 
                    {
                        $image = $SvcReg.ImagePath
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name ImagePath -Value "`"$image`""
                        $SvcReg |Select-Object PSChildName  | out-file $lpath -Append
                        $SvcReg |Select-Object ImagePath  | out-file $lpath -Append
                    }
                }
    }
    UnQuoted