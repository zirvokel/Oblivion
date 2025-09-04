Import-Module ActiveDirectory -ErrorAction Stop

$ad      = Get-ADDomain
$NetBIOS = $ad.NetBIOSName

switch ($NetBIOS) {
  'DOM1'    { $Suffix='.dmz'; $GroupName='DMZ_2_ADM'; $SharePath='\\192.168.10.2\Transactions'; $SvcName='svc_relay_dom1' }
  'DOM2'    { $Suffix='.adm'; $GroupName='DMZ_2_ADM'; $SharePath='\\10.10.240.2\Transactions' ; $SvcName='svc_relay_dom2' }
  'DOMAIN1' { $Suffix='.dmz'; $GroupName='DMZ_2_ADM'; $SharePath='\\192.168.10.2\Transactions'; $SvcName='svc_relay_dom1' }
  'DOMAIN2' { $Suffix='.adm'; $GroupName='DMZ_2_ADM'; $SharePath='\\10.10.240.2\Transactions' ; $SvcName='svc_relay_dom2' }
  default   { Write-Host "Domaine inattendu: $NetBIOS" -ForegroundColor Red; exit 1 }
}

$FirstName = Read-Host "Prénom"
$LastName  = Read-Host "Nom"
$SamBase   = Read-Host "Login de base (ex: jdupont)"
$Password  = Read-Host "Mot de passe initial" -AsSecureString

if ([string]::IsNullOrWhiteSpace($FirstName) -or
    [string]::IsNullOrWhiteSpace($LastName)  -or
    [string]::IsNullOrWhiteSpace($SamBase)) {
  Write-Host "Champs obligatoires manquants." -ForegroundColor Red
  exit 1
}

$Sam = "$SamBase$Suffix"
$UPN = "$Sam@$($ad.DNSRoot)"

function Resolve-LocalPath {
  param([Parameter(Mandatory)][string]$SharePath)

  $thisNames = @(
    $env:COMPUTERNAME,
    "$($env:COMPUTERNAME).$($ad.DNSRoot)"
  ) + (Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress | ForEach-Object { $_.ToString() })

  if ($SharePath -match '^\\\\([^\\]+)\\(.+)$') {
    $TargetHost = $Matches[1]
    $ShareName  = $Matches[2]
    if ($thisNames -contains $TargetHost) {
      return "C:\$ShareName"
    }
  }
  return $SharePath
}

function Invoke-Cmd {
  param([Parameter(Mandatory)][string]$CommandLine)
  $full = "/c $CommandLine >NUL 2>&1"
  $p = Start-Process -FilePath "cmd.exe" -ArgumentList $full -NoNewWindow -PassThru -Wait
  return $p.ExitCode
}

function Invoke-Icacls {
  param(
    [Parameter(Mandatory)][string]$Args,
    [int]$Retry = 3
  )
  for ($i=1; $i -le $Retry; $i++) {
    $rc = Invoke-Cmd -CommandLine ("icacls " + $Args)
    if ($rc -eq 0) { return $true }
    Start-Sleep -Milliseconds 250
  }
  return $false
}

function Ensure-Ownership {
  param([Parameter(Mandatory)][string]$Path)
  $pQuoted = '"' + $Path + '"'

  $null = Invoke-Cmd -CommandLine "takeown /F $pQuoted /A /R /D Y"
  if ($LASTEXITCODE -ne 0) { $null = Invoke-Cmd -CommandLine "takeown /F $pQuoted /A /R /D O" }
  if ($LASTEXITCODE -ne 0) { $null = Invoke-Cmd -CommandLine "takeown /F $pQuoted /A /R" }

  $null = Invoke-Cmd -CommandLine "icacls $pQuoted /setowner `"*S-1-5-32-544`" /T /C"
}

$SID_CREATOR_OWNER = "*S-1-3-0"
$SID_SYSTEM        = "*S-1-5-18"
$SID_BUILTIN_USERS = "*S-1-5-32-545"
$SID_AUTH_USERS    = "*S-1-5-11"
$SID_EVERYONE      = "*S-1-1-0"

$DomainAdminsSid    = ($ad.DomainSID.Value.Trim()) + "-512"
$SID_DOMAIN_ADMINS  = "*$DomainAdminsSid"

if (-not (Get-ADGroup -Filter 'Name -eq "DMZ_2_ADM"' -ErrorAction SilentlyContinue)) {
  New-ADGroup -Name $GroupName -SamAccountName $GroupName -GroupScope Global `
    -Path "OU=Groupes,$($ad.DistinguishedName)" `
    -Description "Autorisation d'utiliser la passerelle Transactions" | Out-Null
  Write-Host "Groupe $GroupName créé." -ForegroundColor Yellow
}

if (-not (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue)) {
  New-ADUser `
    -Name "$FirstName $LastName" `
    -SamAccountName $Sam `
    -UserPrincipalName $UPN `
    -GivenName $FirstName `
    -Surname $LastName `
    -AccountPassword $Password `
    -Enabled $true `
    -ChangePasswordAtLogon $true `
    -Path "OU=Utilisateurs,$($ad.DistinguishedName)"
  Write-Host "Utilisateur $Sam créé." -ForegroundColor Green
} else {
  Write-Host "Utilisateur $Sam existe déjà (aucune création)." -ForegroundColor Yellow
}

try {
  Add-ADGroupMember -Identity $GroupName -Members $Sam -ErrorAction Stop
  Write-Host "Ajouté au groupe $GroupName." -ForegroundColor Green
} catch {
  if (-not ($_ -match 'already a member')) {
    Write-Host "Impossible d'ajouter au groupe $GroupName : $_" -ForegroundColor Red
  } else {
    Write-Host "Déjà membre de $GroupName." -ForegroundColor Yellow
  }
}

$ShareLocal = Resolve-LocalPath -SharePath $SharePath
if (-not (Test-Path $ShareLocal)) { New-Item -ItemType Directory -Path $ShareLocal -Force | Out-Null }

$UserRoot = Join-Path $ShareLocal $Sam
$InPath   = Join-Path $UserRoot 'IN'
$OutPath  = Join-Path $UserRoot 'OUT'

if (-not (Test-Path $UserRoot)) { New-Item -ItemType Directory -Path $UserRoot -Force | Out-Null }
New-Item -ItemType Directory -Force -Path $InPath, $OutPath | Out-Null
Start-Sleep -Milliseconds 200

Ensure-Ownership -Path $UserRoot

$null = Invoke-Icacls ("`"$UserRoot`" /inheritance:r")
$null = Invoke-Icacls ("`"$UserRoot`" /remove:g `"$(${SID_BUILTIN_USERS})`" `"$(${SID_AUTH_USERS})`"")
$null = Invoke-Icacls ("`"$UserRoot`" /remove:g `"$(${SID_EVERYONE})`"")

$null = Invoke-Icacls ("`"$UserRoot`" /grant:r `"$(${SID_CREATOR_OWNER}):(OI)(CI)(IO)(F)`"")

$null = Invoke-Icacls ("`"$UserRoot`" /grant:r `"$(${SID_SYSTEM}):(OI)(CI)(F)`"")
$null = Invoke-Icacls ("`"$UserRoot`" /grant:r `"$(${SID_DOMAIN_ADMINS}):(OI)(CI)(F)`"")

$SvcAccount  = "$NetBIOS\$SvcName"
$UserAccount = "$NetBIOS\$Sam"
$null = Invoke-Icacls ("`"$UserRoot`" /grant:r `"$($SvcAccount):(OI)(CI)(M)`"")
$null = Invoke-Icacls ("`"$UserRoot`" /grant:r `"$($UserAccount):(OI)(CI)(M)`"")

$null = Invoke-Icacls ("`"$InPath`"  /inheritance:e")
$null = Invoke-Icacls ("`"$OutPath`" /inheritance:e")

$ShareName = Split-Path -Path $ShareLocal -Leaf
$UNC = "\\$($env:COMPUTERNAME)\$ShareName\$Sam"

Write-Host ""
Write-Host "  Utilisateur: $Sam" -ForegroundColor Green
Write-Host "  Dossiers: $UNC (IN/OUT)" -ForegroundColor Green
Write-Host "  ACL appliquées :" -ForegroundColor Green
Write-Host "   - CREATOR OWNER (SID *S-1-3-0) (IO)(F)"
Write-Host "   - SYSTEM (SID *S-1-5-18) (F)"
Write-Host "   - $UserAccount (M)"
Write-Host "   - $SvcAccount (M)"
Write-Host "   - Domain Admins ($SID_DOMAIN_ADMINS) (F)"