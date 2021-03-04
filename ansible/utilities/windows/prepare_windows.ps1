Set-Service -Name "WinRM" -StartupType Automatic
Start-Service -Name "WinRM"

if (-not (Get-PSSessionConfiguration) -or (-not (Get-ChildItem WSMan:\localhost\Listener))) {
    ## Use SkipNetworkProfileCheck to make available even on Windows Firewall public profiles
    ## Use Force to not be prompted if we're sure or not.
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
}

Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true

$testUserAccountName = 'temp-admin'
$testUserAccountPassword = (ConvertTo-SecureString -String 'ChangePassword!' -AsPlainText -Force)
if (-not (Get-LocalUser -Name $testUserAccountName -ErrorAction Ignore)) {
    $newUserParams = @{
        Name                 = $testUserAccountName
        AccountNeverExpires  = $true
        PasswordNeverExpires = $true
        Password             = $testUserAccountPassword
    }
    $null = New-LocalUser @newUserParams
}

##KEY GENERATED ON LINUX HERE

$pubKeyFilePath = 'C:\Users\Administrator\Desktop\cert.pem'

## Import the public key into Trusted Root Certification Authorities and Trusted People
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\Root'
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'

$hostname = hostname
$serverCert = New-SelfSignedCertificate -DnsName $hostName -CertStoreLocation 'Cert:\LocalMachine\My'

$httpsListeners = Get-ChildItem -Path WSMan:\localhost\Listener\ | where-object { $_.Keys -match 'Transport=HTTPS' }
if ((-not $httpsListeners) -or -not (@($httpsListeners).where( { $_.CertificateThumbprint -ne $serverCert.Thumbprint }))) {
    $newWsmanParams = @{
        ResourceUri = 'winrm/config/Listener'
        SelectorSet = @{ Transport = "HTTPS"; Address = "*" }
        ValueSet    = @{ Hostname = $hostName; CertificateThumbprint = $serverCert.Thumbprint }
        # UseSSL = $true
    }
    $null = New-WSManInstance @newWsmanParams
}

$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $testUserAccountName, $testUserAccountPassword

$ansibleCert = Get-ChildItem -Path 'Cert:\LocalMachine\Root' | Where-Object {$_.Subject -eq 'CN=ansibletestuser'}

$params = @{
	Path = 'WSMan:\localhost\ClientCertificate'
	Subject = "$testUserAccountName@localhost"
	URI = '*'
	Issuer = $ansibleCert.Thumbprint
  Credential = $credential
	Force = $true
}
New-Item @params

$newItemParams = @{
    Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Name         = 'LocalAccountTokenFilterPolicy'
    Value        = 1
    PropertyType = 'DWORD'
    Force        = $true
}
$null = New-ItemProperty @newItemParams

$ruleDisplayName = 'Windows Remote Management (HTTPS-In)'
if (-not (Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction Ignore)) {
    $newRuleParams = @{
        DisplayName   = $ruleDisplayName
        Direction     = 'Inbound'
        LocalPort     = 5986
        RemoteAddress = 'Any'
        Protocol      = 'TCP'
        Action        = 'Allow'
        Enabled       = 'True'
        Group         = 'Windows Remote Management'
    }
    $null = New-NetFirewallRule @newRuleParams
}

Get-LocalUser -Name $testUserAccountName | Add-LocalGroupMember -Group 'Administrators'

winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
