# Macro Analysis
  Windows.Applications.OfficeMacros
  Look for ineresting function and windows api calls such as virtualprotect..etc
# for files found in step 1
  Windows.Search.FileFinder
    Task - Label all Identified Clients with specific label
        
        
        label(client_id=ClientId, labels="victim", op="set")
        
  Windows.Registry.EnabledMacro
  Windows.Applications.OfficeMacros.MacroRaptor
# Hunt for template  Injection
# Browser Analysis
 ## Windows.Applications.Chrome.History 
       
      SELECT * FROM source(artifact="Windows.Applications.Chrome.History")
      WHERE visit_count < 2
      
# Hunt for ISO/IMG file mounting
    Windows.Detection.ISOMount - FlowID F.CNO4518FU87IG
# Powershell Analysis
