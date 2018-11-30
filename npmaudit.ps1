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
    [ValidateSet($true, $false)]  
    [bool]$includeDevDeps = $false,
    [string]$depth = "",
    [string]$outputFileVuln = "",
    [ValidateSet($true, $false)]  
    [bool]$silent = $false,
    [ValidateSet($true, $false)]  
    [bool]$generateAttributions = $false,
    [string]$attributionsOutputFile = "ATTRIBUTIONS"

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
    'AFL-2.1',
    'AFLv2.1,BSD',
    'AFL-3.0',
    'ASL-1.1',
    'Boost Software License',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'CC-BY',
    'MS-PL',
    'ISC'    
    ) -join ";"

$prohibitedLicenses = @()

# TODO: add prereq check on license-checker

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
        npm install --no-audit --silent | Out-Null
    }
    else 
    {
        # we don't need to actually install for vuln check
        npm install --package-lock-only --no-audit --silent | Out-Null
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

        if ($includeDevDeps)
        {
            $productionFlag = ""
        }
        else
        {
            $productionFlag = "--production"
        }

        Write-Host "Checking licenses"

        if ($depth) 
        {
            Write-Host "Cleaning-up non-top level dependencies"
            $prodDepList = $(npm ls $productionFlag --depth $depth --parseable --silent 2>$null)          
            Get-ChildItem -Path .\node_modules\ | Where-Object {$_.FullName -notin $prodDepList} | Remove-Item -Force -Recurse
        }

        Write-Host "Running license-checker"
        $summary = $(license-checker $productionFlag --onlyAllow "$allowedLicenses" --summary)
            
        if ($LASTEXITCODE -ne 0) 
        {
            $licenseCheckStatus = "FAILED"
            # get summary for breakdown
            $summary = $(license-checker $productionFlag --summary)
        }        
    }

    if ($generateAttributions) 
    {
        Write-Host "Generating license attributions file"
        $licenseFiles = Get-ChildItem -Path .\node_modules\*\LICENSE
        #TODO: add output file name option
        foreach ($license in $licenseFiles)
        {
            #Write-Host "Found LICENSE file in: $license"
            $attributionsList += "="*$($license.Directory.Name).Length + 
                "`r`n$($license.Directory.Name)`r`n"+ "="*$($license.Directory.Name).Length +"`r`n"
            $attributionsList += $(Get-Content -Path $license -Encoding UTF8 -Raw)
            $attributionsList += "`r`n"
        }
    }
    
    $attributionsList | Out-File -FilePath $attributionsOutputFile

    if (-Not $silent)
    {
        if (($checks -eq "vulnerabilities") -Or ($checks -eq "all"))
        {
            Write-Host "--------------------"
            Write-Host "Vulnerability check: $vulnCheckStatus"
            Write-Host "--------------------"
            Write-Host "Found: $($findingsVuln.Count) vulnerabilities. Low: $lowCount - Moderate: $moderateCount - High: $highCount"
    
            if ($($findingsVuln.Count) -gt 0)
            {
                Write-Host $($findingsVuln | ConvertTo-Json)
            }
        }
        
        Write-Host "-------------------------"
        Write-Host "License compliance check: $licenseCheckStatus"
        Write-Host "-------------------------"
        Write-Host "License breakdown:"
        foreach ($line in $summary) 
        {
            # otherwise, line breaks are gone :/
            Write-Host "$line"
        }
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
