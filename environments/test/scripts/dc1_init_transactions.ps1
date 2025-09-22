Import-Module ActiveDirectory -ErrorAction Stop
Import-Module SmbShare -ErrorAction Stop

$domain   = Get-ADDomain
$netbios  = $domain.NetBIOSName
$domainDN = $domain.DistinguishedName
$shareRoot= 'C:\Transactions'
$shareName= 'Transactions'
$group    = 'DMZ_2_ADM'
$svc      = 'svc_relay_dom1'

Write-Host "Domaine: $($domain.DNSRoot) ($netbios)"

# OUs
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Groupes du domaine'")) {
    New-ADOrganizationalUnit -Name 'Groupes du domaine' -Path $domainDN
    Write-Host "OU Créée: Groupes du domaine"
} else {
    Write-Host "OU Ok: Groupes du domaine"
}

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Utilisateurs du domaine'")) {
    New-ADOrganizationalUnit -Name 'Utilisateurs du domaine' -Path $domainDN
    Write-Host "OU Créée: Utilisateurs du domaine"
} else {
    Write-Host "OU Ok: Utilisateurs du domaine"
}

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Comptes de service'")) {
    New-ADOrganizationalUnit -Name 'Comptes de service' -Path $domainDN
    Write-Host "OU Créée: Comptes de service"
} else {
    Write-Host "OU Ok: Comptes de service"
}

# Groupe
$groupsOU = "OU=Groupes du domaine,$domainDN"
if (-not (Get-ADGroup -Filter "SamAccountName -eq '$group'")) {
  New-ADGroup -Name $group -SamAccountName $group -GroupCategory Security -GroupScope Global -Path $groupsOU | Out-Null
  Write-Host "Groupe créé: $group"
} else {
  Write-Host "Groupe OK: $group"
}

# Compte service
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

# Partage
if (-not (Test-Path $shareRoot)) { New-Item -ItemType Directory -Path $shareRoot -Force | Out-Null }
if (-not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
  $domainAdmins = "$netbios\Domain Admins"
  New-SmbShare -Name $shareName -Path $shareRoot `
    -FullAccess @("NT AUTHORITY\SYSTEM",$domainAdmins) `
    -ChangeAccess @("$netbios\$svc","$netbios\$group") | Out-Null
  Set-SmbShare -Name $shareName -FolderEnumerationMode AccessBased -Confirm:$false | Out-Null
  Set-SmbShare -Name $shareName -EncryptData $true -Confirm:$false | Out-Null
  Write-Host "Partage créé: \\$env:COMPUTERNAME\$shareName"
} else {
  Write-Host "Partage OK: \\$env:COMPUTERNAME\$shareName"
}

# NTFS (noms neutres)
$domainAdmins = "$netbios\Domain Admins"
$aceAdmins = "$domainAdmins:(OI)(CI)(F)"
$aceSvc    = "$netbios\${svc}:(OI)(CI)(M)"
$aceGroup  = "$netbios\${group}:(RX)"

icacls $shareRoot /inheritance:d | Out-Null
icacls $shareRoot /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" "$aceAdmins" "$aceSvc" "$aceGroup" | Out-Null
# Supprime Usagers FR/EN s'ils existent
icacls $shareRoot /remove:g "Users" "Authenticated Users" "Utilisateurs" "Utilisateurs authentifiés" 2>$null | Out-Null

# Provision IN/OUT pour les membres "utilisateurs" du groupe
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
  icacls $uRoot /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" "$aceAdmins" "$aceSvc" "$aceUser" | Out-Null
  icacls $uRoot /remove:g "Users" "Authenticated Users" "Utilisateurs" "Utilisateurs authentifiés" 2>$null | Out-Null
  Write-Host " - $name : IN/OUT + ACL OK"
}

Write-Host "Partage: \\$env:COMPUTERNAME\$shareName"
