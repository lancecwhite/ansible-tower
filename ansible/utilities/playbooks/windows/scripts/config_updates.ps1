$mainURL = "https://www.catalog.update.microsoft.com/Search.aspx?q="
$currentDate = Get-Date -Format "yyyy-MM"
$targetOS = "2019"
If(!(test-path C:\inetpub\wwwroot\$targetOS\$currentDate\))
{
    New-Item -Path "C:\inetpub\wwwroot\$targetOS\" -Name "$currentDate" -ItemType Directory -Force
}
$fullURL = "$mainURL$currentDate%20$targetOS"
$tagFile = "C:\Automation\windows_update.tag"
$tagFileRun = "C:\inetpub\wwwroot\$targetOS\$currentDate\windows_update.tag"
$content = Get-Content $tagFile
$content -replace '(^https\:\/\/.*$)',"$fullURL" | Set-Content $tagFileRun
cmd /c C:\tagui\src\tagui $tagFileRun -h
