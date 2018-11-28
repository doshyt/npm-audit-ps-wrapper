<#
.SYNOPSIS

Script to generate information about vulnerable js libraries
in an automation-ready form based on npm-audit.

.DESCRIPTION

This script simply runs npm-audit and parses the output.
Allows to fail on threshold severity, exclude devDependencies
and save result as json.

.PARAMETER targetFolder
Folder with package.json file.

.PARAMETER failOnVulnLevel
Specifies threshold of vulnerability severity level that makes script to exit with code 1.
Allowed values: none, low, moderate, high.

.PARAMETER includeDevDeps
Whether to report vulnerabilities for devDependencies.
Allowed values: $true, $false

.PARAMETER outputFileVuln
Output file for resulting json object. When empty, result are printed to console.

.PARAMETER silent
Supress output.
Allowed values: $true, $false

.EXAMPLE

C:\PS> npmaudit.ps1 -targetFolder "myFolder" -failOnVulnLevel moderate -outputFileVuln result.json

#>

param (
    [ValidateSet('all','licenses','vulnerabilities')]    
    [string]$checks = "all",
    [string]$targetFolder = ".",
    [ValidateSet('none','low','moderate','high')]
    [string]$failOnVulnLevel = "none",
    [bool]$includeDevDeps = $false,
    [string]$outputFileVuln = "",
    [bool]$silent = $false
)

if (-Not (Test-Path $targetFolder\package.json))
{
    Write-Host "ERR! Required file package.json doesn't exist in specified location"
    Exit 1
}

$findingsVuln = @()
$highCount = 0
$moderateCount = 0
$lowCount = 0
$vulnCheckStatus = "OK"
$licenseCheckStatus = "OK"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$allowedLicenses = @(
    'MIT',
    'MIT*',
    'Apache-2.0',
    'AFL 2.1',
    'AFL 3.0',
    'ASL 1.1',
    'Boost Software License',
    'BSD-2-Clause',
    'BSD-3-clause',
    'CC-BY',
    'MS-PL',
    'ISC'    
    ) -join ";"

$prohibitedLicenses = @()

Push-Location
Set-Location $targetFolder

Rename-Item -Path package.json -NewName package.json.original
try
{
    $content = (Get-Content -Raw -Path package.json.original | ConvertFrom-Json)
    if (-Not $includeDevDeps)
    {
        $content.PSObject.Properties.Remove('devDependencies')
    }

    $content | ConvertTo-Json | Out-File package.json -Encoding ASCII
    if (-Not $silent) { Write-Host "Resolving dependencies" }
    
    if (($checks -eq "all") -Or ($checks -eq "licenses"))
    {
        npm install --no-audit | Out-Null
    }
    else 
    {
        # we don't need to actually install for vuln check
        npm install --package-lock-only --no-audit | Out-Null
    }
    
    if (($checks -eq "vulnerabilities") -Or ($checks -eq "all"))
    {
        if (-Not $silent) { Write-Host "Looking for vulnerabilities in dependencies" }

        $audit = $(npm audit -j | ConvertFrom-Json)

        foreach ($finding in $audit.advisories.PSObject.Properties)
        {
            $finding
            switch ($finding.Value.severity)
            {
                "high" { $highCount += 1}
                "moderate" { $moderateCount += 1}
                "low" { $lowCount += 1 }
            }
    
            $findingsVuln += @{
                "VulnerabilitySource" = "$($finding.Value.module_name)"
                "VulnerabilityTitle" = "$($finding.Value.title)"
                "VulnerabilitySeverity" = "$($finding.Value.severity)"
                "VulnerabilityChains" = $finding.Value.findingsVuln.paths
                "VulnerableVersions" = "$($finding.Value.vulnerable_versions)"
                "PatchedVersions" = "$($finding.Value.patched_versions)"
                "AdvisoryUrl" = "$($finding.Value.url)"
            }
        }
    }
    
    if ($($findingsVuln.Count) -gt 0) {
        $vulnCheckStatus = "FAIL"
    }
    
    if (($checks -eq "licenses") -Or ($checks -eq "all")) 
    {
        Write-Host "Checking licenses"
        npm install --production | Out-Null
        # get and remove not top-level dependencies
        $prodDepList = $(npm ls --prod --depth 0 --parseable)
        Get-ChildItem -Path .\node_modules\ | Where-Object {$_.FullName -notin $prodDepList} | Remove-Item -Force -Recurse
        try {
            $summary = $(license-checker --production --onlyAllow "$allowedLicenses" --summary)
        }
        catch {
            $licenseCheckStatus = "FAILED"
        }
        
    }

    if (-Not $silent)
    {

        Write-Host "--------------------"
        Write-Host "Vulnerability check: $vulnCheckStatus"
        Write-Host "--------------------"
        Write-Host "Found: $($findingsVuln.Count) vulnerabilities. Low: $lowCount - Moderate: $moderateCount - High: $highCount"

        if ($($findingsVuln.Count) -gt 0)
        {
            Write-Host $($findingsVuln | ConvertTo-Json)
        }
        Write-Host "-------------------------"
        Write-Host "License compliance check: $licenseCheckStatus"
        Write-Host "-------------------------"
        Write-Host "License breakdown:"
        Write-Host "$summary"
    }

    if ($outputFileVuln)
    {
        $findingsVuln | ConvertTo-Json | Out-File $outputFileVuln -Encoding ASCII
    }

}
catch
{
    Write-Host "Error occurred: $($_.Exception)"
}
finally
{
    Remove-Item -Path package.json
    Rename-Item -Path package.json.original -NewName package.json
    Pop-Location

    switch ($failOnVulnLevel)
    {
        "high" { if ($highCount -gt 0) { Exit 1 } }
        "moderate" { if (($moderateCount -gt 0) -Or ($highCount -gt 0)) { Exit 1 } }
        "low" { if (($moderateCount -gt 0) -Or ($highCount -gt 0) -Or ($lowCount -gt 0)) { Exit 1 } }
        "none" { Exit 0 }
    }
}
