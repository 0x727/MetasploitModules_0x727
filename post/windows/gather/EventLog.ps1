#运行 *.ps1 (管理员)    set-executionpolicy remotesigned
#安全日志导出，管理员权限 wevtutil.exe epl Security C:\Windows\Temp\Security.evtx
#EventID=4624 成功登录
#EventID=4625 失败登录
#Logon type 3 Network 网络登录
#Logon Type 10 RemoteInteractive 远程登录

### 放在 Metasploit 的 /data/post/powershell 目录下 ###

Param (
    [string]$evtx = $pwd.Path+"\*_Security.evtx"
    # [string]$evtx = "C:\Windows\Temp\Security.evtx"
)

$time=Get-Date -Format h:mm:ss
$evtx=(Get-Item $evtx).fullname
$outfile="C:\Windows\Temp\"+(Get-Item $evtx).BaseName+".csv"

$logsize=[int]((Get-Item $evtx).length/1MB)

write-host [+] $time Load $evtx "("Size: $logsize MB")" ... -ForegroundColor Green
[xml]$xmldoc=WEVTUtil qe  $evtx /q:"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing']  and (EventID=4624 or EventID=4625)] and EventData[Data[@Name='LogonType']='3'] or EventData[Data[@Name='LogonType']='10']]" /e:root /f:Xml  /lf

$xmlEvent=$xmldoc.root.Event

function OneEventToDict {
    Param (
        $event
    )
    $ret = @{
        "SystemTime" = $event.System.TimeCreated.SystemTime | Convert-DateTimeFormat -OutputFormat 'yyyy"/"MM"/"dd HH:mm:ss';
        "EventID" = $event.System.EventID
    }
    $data=$event.EventData.Data
    for ($i=0; $i -lt $data.Count; $i++){
        $ret.Add($data[$i].name, $data[$i].'#text')
    }
    return $ret
}

filter Convert-DateTimeFormat
{
  Param($OutputFormat='yyyy-MM-dd HH:mm:ss fff')
  try {
    ([DateTime]$_).ToString($OutputFormat)
  } catch {}
}

$time=Get-Date -Format h:mm:ss
write-host [+] $time Extract XML ... -ForegroundColor Green
[System.Collections.ArrayList]$results = New-Object System.Collections.ArrayList($null)
for ($i=0; $i -lt $xmlEvent.Count; $i++){
    $event = $xmlEvent[$i]
    $datas = OneEventToDict $event

    $results.Add((New-Object PSObject -Property $datas))|out-null
}

$time=Get-Date -Format h:mm:ss
write-host [+] $time Dump into CSV: $outfile ... -ForegroundColor Green
$results | Select-Object SystemTime,IpAddress,TargetDomainName,TargetUserName,EventID,LogonType | Export-Csv $outfile -NoTypeInformation -UseCulture  -Encoding Default -Force