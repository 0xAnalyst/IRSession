# Webshell Analysis
Use the following yara with the artifact Windows.Search.FileFinder filtering for asp and aspx files

rule CMD : webshell
{
	meta:
	
	    author		= "foo"
	    
	strings:
		$a = "cmd.exe" wide ascii nocase fullword
		$b = "xp_cmdshell" wide ascii nocase
		$c = /eval\s*\(/	wide ascii nocase
		$d = "system.diagnostics" wide ascii nocase fullword
		$e = "system.net.networkinformation" wide ascii nocase fullword
		$f = "Microsoft.Management" wide ascii fullword
		$m = "system.data.sqlclient" wide ascii nocase fullword
	condition:
		any of them
}

Use artifcat Generic.Detection.WebShells
