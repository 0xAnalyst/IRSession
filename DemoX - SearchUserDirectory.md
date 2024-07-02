# Identify PE files recursively in user directory
```
SELECT FullPath, hash(path=FullPath).SHA256 AS SHA256 FROM glob(globs='C:\\Users\\**\\*.exe') WHERE NOT IsDir
```

You can create a custom artifact with that 
Custom.Artifact.Parse.Users.Home.Folder.for.binaries

