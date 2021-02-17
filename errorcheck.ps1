$OutputFile = "C:\Users\Public\Documents\autoconfig\ErrorLog.txt"

if (Test-Path $OutputFile) {
              Add-Type -AssemblyName PresentationFramework
              $msgBoxInput =  [System.Windows.MessageBox]::Show('Erros have been detected, would you like to open the error log?','Error log is present','YesNo','Error')

              switch  ($msgBoxInput) {

              'Yes' {

              notepad "C:\Users\Public\Documents\autoconfig\ErrorLog.txt" 

              }

              'No' {

                [System.Windows.MessageBox]::Show('The configuration is complete!', 
                'Warning', 'Ok','Warning','Ok')


              }
      
            }

}


        else {
             Add-Type -AssemblyName PresentationFramework
                [System.Windows.MessageBox]::Show('The configuration is complete!', 
                'Warning', 'Ok','Warning','Ok')

        }

$Status = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" | where PartialProductKey).licensestatus
If ($Status -ne 1) {[System.Windows.MessageBox]::Show('"Windows is not activated, Please activate now!"', 
                'Warning', 'Ok','Warning','Ok')}



Remove-Item "C:\Users\Public\Documents\autoconfig\" -Include * -Recurse -Exclude errorlog.txt