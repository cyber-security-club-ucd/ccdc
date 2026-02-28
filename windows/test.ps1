$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$filename = "userlist_$timestamp.dns"

Get-ADUser -Filter * | 
Select-Object Name, SamAccountName, UserPrincipalName, Enabled |
Export-Csv $filename -NoTypeInformation

