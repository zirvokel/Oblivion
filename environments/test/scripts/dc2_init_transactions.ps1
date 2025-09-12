Import-Module ActiveDirectory -ErrorAction Stop
Import-Module SmbShare -ErrorAction Stop

$domain   = Get-ADDomain
$netbios  = $domain.NetBIOSName
$domainDN = $domain.DistinguishedName
$shareRoot= 'C:\Transactions'
$shareName= 'Transactions'
$group    = 'DMZ_2_ADM'
$svc      = 'svc_relay_dom2'

Write-Host "Domaine: $($domain.DNSRoot) ($netbios)"

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Domain Groups'")) {
    New-ADOrganizationalUnit -Name 'Domain Groups'
    Write-Host "OU Créée: Domain Groups"
} else {
    Write-Host "OU Ok: Domain Groups"
}

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Domain Users'")) {
    New-ADOrganizationalUnit -Name 'Domain Users'
    Write-Host "OU Créée: Domain Users"
} else {
    Write-Host "OU Ok: Domain Users"
}

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Comptes de service'")) {
    New-ADOrganizationalUnit -Name 'Comptes de service'
    Write-Host "OU Créée: Comptes de service"
} else {
    Write-Host "OU Ok: Comptes de service"
}

if (-not (Get-ADGroup -Filter "SamAccountName -eq '$group'")) {
  New-ADGroup -Name $group -SamAccountName $group -GroupCategory Security -GroupScope Global -Path "OU=Domain Groups,$domainDN" | Out-Null
  Write-Host "Groupe créé: $group"
} else {
  Write-Host "Groupe OK: $group"
}

if (-not (Get-ADUser -Filter "SamAccountName -eq '$svc'")) {
  $password = Read-Host -AsSecureString "Mot de passe pour $svc"
  New-ADUser -Name $svc -SamAccountName $svc -Enabled $true -AccountPassword $password `
    -PasswordNeverExpires $true -CannotChangePassword $true -Path "OU=Comptes de service,$domainDN" `
    -Description "Service relay DOM1" | Out-Null
  Write-Host "Compte service créé: $svc"
} else {
  Write-Host "Compte service OK: $svc"
}
Add-ADGroupMember -Identity $group -Members $svc -ErrorAction SilentlyContinue

if (-not (Test-Path $shareRoot)) { New-Item -ItemType Directory -Path $shareRoot -Force | Out-Null }
if (-not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
  New-SmbShare -Name $shareName -Path $shareRoot `
    -FullAccess @("Système","$netbios\Admins du domaine") `
    -ChangeAccess @("$netbios\$svc","$netbios\$group") | Out-Null
  Set-SmbShare -Name $shareName -FolderEnumerationMode AccessBased -Confirm:$false | Out-Null
  Set-SmbShare -Name $shareName -EncryptData $true -Confirm:$false | Out-Null
  Write-Host "Partage créé: \\$env:COMPUTERNAME\$shareName"
} else {
  Write-Host "Partage OK: \\$env:COMPUTERNAME\$shareName"
}

$aceAdmins = "$netbios\Admins du domaine:(OI)(CI)(F)"
$aceSvc    = "$netbios\${svc}:(OI)(CI)(M)"
$aceGroup  = "$netbios\${group}:(RX)"
icacls $shareRoot /inheritance:d | Out-Null
icacls $shareRoot /grant:r "Système:(OI)(CI)(F)" "$aceAdmins" "$aceSvc" "$aceGroup" | Out-Null
icacls $shareRoot /remove:g "Utilisateurs" "Utilisateurs authentifiés" 2>$null | Out-Null

$members = Get-ADGroupMember -Identity $group -Recursive |
           Where-Object { $_.objectClass -eq 'user' } |
           Get-ADUser -Properties SamAccountName

foreach ($u in $members) {
  $name  = $u.SamAccountName
  if ($name -ieq $svc) { continue }
  $uRoot = Join-Path $shareRoot $name
  $inDir = Join-Path $uRoot 'IN'
  $outDir= Join-Path $uRoot 'OUT'
  New-Item -ItemType Directory -Force -Path $inDir, $outDir | Out-Null

  $aceUser = "$netbios\${name}:(OI)(CI)(M)"
  icacls $uRoot /inheritance:d | Out-Null
  icacls $uRoot /grant:r "Système:(OI)(CI)(F)" "$aceAdmins" "$aceSvc" "$aceUser" | Out-Null
  icacls $uRoot /remove:g "Utilisateurs" "Utilisateurs authentifiés" 2>$null | Out-Null
  Write-Host " - $name : IN/OUT + ACL OK"
}

Write-Host "Partage: \\$env:COMPUTERNAME\$shareName"
