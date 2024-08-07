# Create a custom artifact with the following 
make sure to change hollws_hunter binary to the latest version

```
name: Custom.Windows.Detection.ProcessHollowing
description: |
   Use hollows_hunter to detect suspicious process injections.
   
   Upload any findings to the server, including process dumps.
tools:
 - name: hollows_hunter
   url: https://github.com/hasherezade/hollows_hunter/releases/download/v0.2.7.1/hollows_hunter64.exe

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'

    query: |
      -- Get the path to the hollows_hunter tool and a fresh temp directory.
      LET binaries <= SELECT FullPath, tempdir() AS TempDir 
      FROM Artifact.Generic.Utils.FetchBinary(
         ToolName="hollows_hunter")
      
      -- Run the tool and relay back the output, as well as upload all the files from the tempdir.
      SELECT * FROM chain(
      a={SELECT Stdout, NULL AS Upload
         FROM execve(argv=[binaries[0].FullPath,     
           "/json", "/dir", binaries[0].TempDir], length=100000)},
      b={
        SELECT upload(file=FullPath) AS Upload
        FROM glob(globs="*", root=binaries[0].TempDir)
      })
      ```
