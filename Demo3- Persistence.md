# Task Schedular

```

SELECT Computer, EventData.TaskName, EventData.Path, count() as count FROM source(artifact="Windows.EventLogs.ScheduledTasks")
GROUP BY `EventData.TaskName`
stak and count by Command and arguments

SELECT * , count() as Count FROM hunt_results( artifact='Windows.System.TaskScheduler/Analysis', hunt_id='H.054955d4') WHERE Command=~ "cmd.exe" GROUP BY Command, Arguments
```

# Startup Items
# Services
# WMI Event consumer
