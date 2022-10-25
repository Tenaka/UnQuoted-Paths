   
    <#
    .Synopsis
    Checks for unquoted path vulnerbilities and updates the registry paths by inserting the required double quotes.
   
    .DESCRIPTION
   
    .EXAMPLE
    
    .VERSION
    210617.01 - Created
    221025.01 - Updated to fix issue where .sys files 
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
    $vulnSvc = Get-CimInstance win32_service | foreach{$_} | 
    where {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | 
    where {-not $_.pathname.startswith("`"")} | 
    where {($_.pathname.substring(0, $_.pathname.indexof(".sys") + 4 )) -match ".* .*" -or ($_.pathname.substring(0, $_.pathname.indexof(".exe") + 4 )) -match ".* .*" }
    $fragUnQuoted=@()
    
    foreach ($unQSvc in $vulnSvc)
    {
    $svc = $unQSvc.name
    $SvcReg = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\$svc -ErrorAction SilentlyContinue
    
        if ($SvcReg.imagePath -like "*.exe*")
        {
            $SvcRegSp =  $SvcReg.imagePath -split ".exe"
            $SvcRegSp0 = $SvcRegSp[0]
            $SvcRegSp1 = $SvcRegSp[1]
            $image = "`"$SvcRegSp0" + ".exe`""+  " " + $SvcRegSp1
            $SvcReg |Select-Object PSChildName,ImagePath  | out-file $qpath -Append
                
            $newObjSvc = New-Object psObject
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name ServiceName -Value "Warning - $($SvcReg.PSChildName) warning"
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name Path -Value "Warning - $($SvcReg.ImagePath) warning"
            $fragUnQuoted += $newObjSvc
        }
    
        if ($SvcReg.imagePath -like "*.sys*")
        {
            $SvcRegSp =  $SvcReg.imagePath -split ".sys"
            $SvcRegSp0 = $SvcRegSp[0]
            $SvcRegSp1 = $SvcRegSp[1]
            $image = "`"$SvcRegSp0" + ".sys`""+   " $SvcRegSp1"
            $SvcReg |Select-Object PSChildName,ImagePath  | out-file $qpath -Append
                       
            $newObjSvc = New-Object psObject
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name ServiceName -Value "Warning - $($SvcReg.PSChildName) warning"
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name Path -Value "Warning - $($SvcReg.ImagePath) warning"
            $fragUnQuoted += $newObjSvc
        }

    }
