# Disposable synthetic A1-H brokers only. No project secrets or real broker.
$ErrorActionPreference='Stop'
$pocDir=(Resolve-Path 'experiments/mosquitto_observer').Path
$suffix=[Guid]::NewGuid().ToString('N').Substring(0,10)
$network="azta-a1h-$suffix"
$image='eclipse-mosquitto:2.1.2-alpine@sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408'
$runtime='azta-journal-runtime:gate3'
$admin=[Guid]::NewGuid().ToString('N')
$a=[Guid]::NewGuid().ToString('N')
$b=[Guid]::NewGuid().ToString('N')
$r=[Guid]::NewGuid().ToString('N')
$created=@();$results=@()
function Check($step) { if($LASTEXITCODE -ne 0){throw "$step failed: $LASTEXITCODE"} }
function Logs($name) {
    $ErrorActionPreference='Continue'
    try {$lines=docker logs $name 2>&1} finally {$ErrorActionPreference='Stop'}
    Check 'logs';return $lines
}
try {
    $null=docker network create --driver bridge --internal --label "azta.a1h=$suffix" $network
    Check 'network'
    foreach($mode in @('baseline','observer','disabled','limit','invalid')){
        $name="a1h-broker-$suffix-$mode"
        $config=if($mode -in @('baseline','observer')){"broker-$mode.conf"}else{$mode}
        $args=@('run','-d','--pull','never','--network',$network,'--name',$name,'--label',"azta.a1h=$suffix",
            '--tmpfs','/tmp:rw,nosuid,nodev,mode=1777','--tmpfs','/mosquitto/data:rw','--tmpfs','/mosquitto/log:rw',
            '--mount',"type=bind,source=$pocDir,target=/poc,readonly",'--env',"POC_ADMIN_PASSWORD=$admin",
            '--env',"POC_CONFIG=$config",'--entrypoint','sh',$image,'/poc/start_broker.sh')
        $null=docker @args;Check 'start';$created+=$name
        if($mode -eq 'invalid'){
            $null=docker wait $name;Check 'invalid wait'
            $exit=docker inspect --format '{{.State.ExitCode}}' $name;Check 'invalid inspect'
            $raw=Logs $name
            if($exit -eq '0' -or ($raw -join '').IndexOf('invalid observation configuration') -lt 0){throw 'Invalid config did not fail fast'}
            Write-Output 'INVALID_CONFIG PASS fail-fast; baseline unaffected'
            $null=docker rm $name;Check 'invalid cleanup';continue
        }
        $ready=$false
        for($i=0;$i -lt 30;$i++){
            $null=docker exec --env "POC_ADMIN_PASSWORD=$admin" $name sh -c 'mosquitto_ctrl -h 127.0.0.1 -u poc-admin -P "$POC_ADMIN_PASSWORD" dynsec getDefaultACLAccess publishClientSend >/dev/null 2>&1' 2>$null
            if($LASTEXITCODE -eq 0){$ready=$true;break}
            Start-Sleep -Milliseconds 200
        }
        if(-not $ready){throw "$mode not ready"}
        $args=@('exec','--env',"POC_ADMIN_PASSWORD=$admin",'--env',"POC_A_PASSWORD=$a",
            '--env',"POC_B_PASSWORD=$b",'--env',"POC_READER_PASSWORD=$r",$name,'sh','/poc/setup_dynsec.sh')
        $null=docker @args;Check 'synthetic policy'
        $args=@('run','--rm','--pull','never','--network',$network,'--read-only','--env','PYTHONDONTWRITEBYTECODE=1',
            '--env',"POC_HOST=$name",'--env',"POC_ADMIN_PASSWORD=$admin",'--env',"POC_A_PASSWORD=$a",
            '--env',"POC_B_PASSWORD=$b",'--env',"POC_READER_PASSWORD=$r",
            '--mount',"type=bind,source=$pocDir\tests,target=/poc/tests,readonly",'--entrypoint','python',
            $runtime,'-B','/poc/tests/synthetic_client.py')
        $output=docker @args;Check "$mode workload"
        $client=($output|Select-Object -Last 1)|ConvertFrom-Json
        $null=docker stop $name;Check 'stop for counters'
        $raw=Logs $name
        foreach($password in @($admin,$a,$b,$r)){if(($raw -join '').Contains($password)){throw 'Credential leak'}}
        if(($raw -join '').Contains('device_id') -or ($raw -join '').Contains('payload-marker')){throw 'Payload leak'}
        $records=@($raw|ForEach-Object{if($_ -match 'AZTA_OBSERVER (\{.*\})'){$Matches[1]|ConvertFrom-Json}})
        $events=@($records|Where-Object record_type -eq EVENT)
        $summary=@($records|Where-Object record_type -eq COUNTERS)
        if($mode -eq 'baseline'){
            if($records.Count){throw 'Baseline observer output'}
        }else{
            if($summary.Count -ne 1){throw 'Missing counters'}
            $c=$summary[0]
            if($c.events_observed -ne ($c.events_emitted+$c.events_filtered+$c.events_malformed_unsupported+$c.events_dropped_limit)){throw 'Counters do not reconcile'}
            if($c.events_emitted -ne $events.Count){throw 'Submitted/persisted mismatch'}
            if(@($events|Where-Object{$_.username -eq 'poc-admin' -or $_.topic -in @('poc/other','poc/forbidden','poc/#')}).Count){throw 'Unrelated/denied event'}
            if($c.events_filtered -lt 1){throw 'Control filtering absent'}
            if($mode -eq 'observer'){
                $in=@($events|Where-Object{$_.event_type -eq 'PUBLISH_IN' -and $_.topic -eq 'poc/shared'})
                foreach($principal in @('poc-a','poc-b')){
                    if(@($in|Where-Object{$_.username -eq $principal -and $_.client_id -eq $principal}).Count -ne 100){throw 'Identity mismatch'}
                }
                if(@($events|Where-Object event_type -eq MESSAGE_OUT).Count -ne 201 -or @($events|Where-Object event_type -eq SUBSCRIBE).Count -ne 1){throw 'Output/subscription mismatch'}
                if(@($events|Where-Object{$_.event_type -eq 'PUBLISH_IN' -and $null -eq $_.topic}).Count -ne 1){throw 'Long topic not bounded'}
                if($events.Count -ne 409 -or $c.events_dropped_limit -ne 0){throw "Scoped count mismatch: $($events.Count)"}
                foreach($principal in @('poc-a','poc-b','poc-reader')){
                    $open=$events|Where-Object{$_.event_type -eq 'CONNECT' -and $_.client_id -eq $principal}
                    $close=$events|Where-Object{$_.event_type -eq 'DISCONNECT' -and $_.client_id -eq $principal}
                    if(-not $open.session_id -or $open.session_id -ne $close.session_id){throw 'Session mismatch'}
                }
            }
            if($mode -eq 'disabled'){
                if(@($events|Where-Object event_type -ne PUBLISH_IN).Count -or $events.Count -ne 201){throw 'Disabled event mismatch'}
            }
            if($mode -eq 'limit'){
                if($events.Count -ne 10 -or @($records|Where-Object record_type -eq LIMIT_REACHED).Count -ne 1 -or $c.events_dropped_limit -ne 399){throw 'Limit mismatch'}
            }
        }
        $results+=[pscustomobject]@{mode=$mode;client=$client;counters=$summary;observer_event_records=$events.Count}
        $null=docker rm $name;Check 'remove'
    }
    foreach($result in $results|Select-Object -Skip 1){
        foreach($field in @('publish_attempted','publish_puback_allowed','publish_puback_denied','subscribe_allowed','subscribe_denied','receiver_messages')){
            if($results[0].client.$field -ne $result.client.$field){throw "Authorization/delivery changed: $field"}
        }
    }
    $results|ForEach-Object{Write-Output ('HARDENING_RESULT '+($_|ConvertTo-Json -Compress -Depth 6))}
}finally{
    foreach($name in $created){
        $exists=docker ps -aq --filter "name=^/$name$"
        if($exists){$null=docker stop $name 2>$null;$null=docker rm $name 2>$null}
    }
    $null=docker network rm $network 2>$null
    $left=docker ps -aq --filter "label=azta.a1h=$suffix"
    $leftNet=docker network ls -q --filter "label=azta.a1h=$suffix"
    if($left -or $leftNet){throw 'Task resources remain'}
    Write-Output 'CLEANUP PASS no task containers/networks remain'
}
