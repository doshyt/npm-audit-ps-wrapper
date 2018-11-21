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

.PARAMETER failOn
Specifies threshold of vulnerability severity level that makes script to exit with code 1.
Allowed values: none, low, moderate, high.

.PARAMETER includeDevDeps
Whether to report vulnerabilities for devDependencies.
Allowed values: $true, $false

.PARAMETER outputFile
Output file for resulting json object. When empty, result are printed to console.

.PARAMETER silent
Supress output.
Allowed values: $true, $false

.EXAMPLE

C:\PS> npmaudit.ps1 -targetFolder "myFolder" -failOn moderate -outputFile result.json

#>

param (
    [string]$targetFolder = ".",
    [ValidateSet('none','low','moderate','high')]
    [string]$failOn = "none",
    [bool]$includeDevDeps = $false,
    [string]$outputFile = "",
    [bool]$silent = $false
)

if (-Not (Test-Path $targetFolder\package.json))
{
    Write-Host "ERR! Required file package.json doesn't exist in specified location"
    Exit 1
}

$findings = @()
$highCount, $moderateCount, $lowCount = 0
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
    npm install --package-lock-only --no-audit | Out-Null
    if (-Not $silent) { Write-Host "Auditing dependencies" }
    $audit = $(npm audit -j | ConvertFrom-Json)

    foreach ($finding in $audit.advisories.PSObject.Properties)
    {
        if ($($finding.Value.severity) -eq "high") {

        }

        switch ($finding.Value.severity)
        {
            "high" { $highCount += 1}
            "moderate" { $moderateCount += 1}
            "low" { $lowCount += 1 }
        }

        $findings += @{
            "VulnerabilitySource" = "$($finding.Value.module_name)"
            "VulnerabilityTitle" = "$($finding.Value.title)"
            "VulnerabilitySeverity" = "$($finding.Value.severity)"
            "VulnerabilityChains" = $finding.Value.findings.paths
            "VulnerableVersions" = "$($finding.Value.vulnerable_versions)"
            "PatchedVersions" = "$($finding.Value.patched_versions)"
            "AdvisoryUrl" = "$($finding.Value.url)"
        }
    }

    if (-Not $silent)
    {
        Write-Host "Found: $($findings.Count) vulnerabilities. Low: $lowCount - Moderate: $moderateCount - High: $highCount"

        if ($($findings.Count) -gt 0)
        {
            Write-Host $($findings | ConvertTo-Json)
        }
    }

    if ($outputFile)
    {
        $findings | ConvertTo-Json | Out-File $outputFile -Encoding ASCII
    }
}
catch
{
    Write-Host "Error occurred: $($_.Exception.Message)"
}
finally
{
    Remove-Item -Path package.json
    Rename-Item -Path package.json.original -NewName package.json
    Pop-Location

    switch ($failOn)
    {
        "high" { if ($highCount -gt 0) { Exit 1 } }
        "moderate" { if (($moderateCount -gt 0) -Or ($highCount -gt 0)) { Exit 1 } }
        "low" { if (($moderateCount -gt 0) -Or ($highCount -gt 0) -Or ($lowCount -gt 0)) { Exit 1 } }
        "none" { Exit 0 }
    }
}
