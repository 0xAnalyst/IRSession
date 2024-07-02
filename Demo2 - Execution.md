# Process List Hunting

        Windows.System.Pslist
        
                    ```SELECT Fqdn,Name, Exe,Hash.SHA256 AS SHA256,Authenticode.Trusted,Username, count() as Count FROM source(artifact="Windows.System.Pslist") GROUP BY Exe ORDER BY Count```


        Generic.System.Pslist

# Process Creation Hunting
    Example VQL
    
        ```SELECT Computer, EventData.TargetUserName as Username, EventData.NewProcessName as NewProcessName, EventData.CommandLine as CommandLine, EventData.ParentProcessName as ParentProcessName, count() as Count
FROM hunt_results(artifact='Windows.EventLogs.EvtxHunter',hunt_id='H.C3ANAA5TITLI2')
GROUP BY ParentProcessName, NewProcessName```


# Bonus Parse NTFS to look for event logs 
```
 SELECT FullPath FROM glob(
globs="C:\Windows\System32\Winevt\Logs\*.evtx",
accessor="ntfs")
```

