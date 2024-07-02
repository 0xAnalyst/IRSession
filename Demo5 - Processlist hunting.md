# Windows.System.Pslist
```
SELECT Fqdn,Name, Exe,Hash.SHA256 AS SHA256,Authenticode.Trusted,Username, count() as Count FROM source(artifact="Windows.System.Pslist")
GROUP BY Exe
ORDER BY Count
```

# Generic.System.Pslist

# Process Creation 
```
SELECT Computer, EventData.TargetUserName as Username, EventData.NewProcessName as NewProcessName, EventData.CommandLine as CommandLine, EventData.ParentProcessName as ParentProcessName, count() as Count
FROM hunt_results(
    artifact='Windows.EventLogs.EvtxHunter',
    hunt_id='H.C3ANAA5TITLI2')
GROUP BY ParentProcessName, NewProcessName

```


