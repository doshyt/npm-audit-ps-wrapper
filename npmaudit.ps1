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
    [ValidateSet('all','check-licenses','find-vulnerabilities', 'generate-attributions')]    
    [string]$action = "all",
    [string]$targetFolder = ".",
    [ValidateSet('none','low','moderate','high')]
    [string]$failOnVulnLevel = "none",
    [ValidateSet($true, $false)]  
    [bool]$includeDevDeps = $false,
    [string]$depth = "0",
    [string]$outputFileVuln = "",
    [ValidateSet($true, $false)]  
    [bool]$silent = $false,  
    [string]$attributionsOutputFile = "ATTRIBUTIONS",
    [ValidateSet($true, $false)]
    [bool]$installPrereqs = $true,
    [string]$pathToLicenseChecker = "",
    [string]$licenseExclusions
)

if ([int]$(npm -v).Split('.')[0] -lt 6 ) 
{
    Write-Host "ERR! npm version must be 6 or greater"
    Exit 1
}

if (-Not (Test-Path $targetFolder\package.json))
{
    Write-Host "ERR! Required file package.json doesn't exist in specified location"
    Exit 1
}

if (-Not $pathToLicenseChecker) 
{
    $pathToLicenseChecker = "license-checker"
    if ( -Not ($(npm -g ls license-checker --parseable) -like "*\license-checker")) 
    {
        if ($installPrereqs) 
        {
            npm install -g license-checker | Out-Null
        }
        else 
        {
            Write-Host "ERR! Required npm package 'license-checker' is not installed globally"
            Exit 1    
        }
    }
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
        
        # handle jspm dependencies
        foreach ($item in $content.jspm.dependencies.PSObject.Properties) 
        {
            $version = $($item.value).Split("@")[1]
            $source = $($item.value).Split(":")[0]

            if ($source -eq "npm") 
            {
                $content.dependencies | Add-Member -MemberType NoteProperty -Name $item.name -Value $version -Force
            }
            else 
            {
                if (-Not $silent) 
                {
                    Write-Host "Detected JSPM dependency which is not in npm: $($item.value)" -ForegroundColor Yellow 
                }
                
            }
            
        }
    }

    $content | ConvertTo-Json | Out-File package.json -Encoding ASCII

    if (-Not $silent) { Write-Host "Resolving dependencies" }
    
    if (($action -eq 'find-vulnerabilities') )
    {
        # we don't need to actually install for vuln check
        npm install --package-lock-only --no-audit --silent | Out-Null
    }
    else 
    {
        npm install --no-audit --silent | Out-Null        
    }
    
    if (($action -eq 'find-vulnerabilities') -Or ($action -eq "all"))
    {
        if (-Not $silent) { Write-Host "Looking for vulnerabilities in dependencies" }

        $audit = $(npm audit -j --registry="https://registry.npmjs.org/" | ConvertFrom-Json )

        foreach ($finding in $audit.advisories.PSObject.Properties)
        {
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
        $vulnCheckStatus = "FAILED"
    }
    
    if (($action -eq 'check-licenses') -Or ($action -eq "all")) 
    {

        if ($includeDevDeps)
        {
            $productionFlag = ""
        }
        else
        {
            $productionFlag = "--production"
        }

        if (-Not $silent) { Write-Host "Checking licenses" }

        if ($depth) 
        {
            if (-Not $silent) { Write-Host "Cleaning-up non-top level dependencies" }
            $prodDepList = $(npm ls $productionFlag --depth $depth --parseable --silent 2>$null)          
            Get-ChildItem -Path .\node_modules\ | Where-Object {$_.FullName -notin $prodDepList} | Remove-Item -Force -Recurse
        }

        if (-Not $silent) { Write-Host "Running $pathToLicenseChecker" }

        if ($licenseExclusions)
        {
            $excludeFlag = "--excludePackages $licenseExclusions"
        }
        $args = "$productionFlag --onlyAllow `"$allowedLicenses`" --summary " + $excludeFlag
        $summary = & "$pathToLicenseChecker" $args
            
        if ($LASTEXITCODE -ne 0) 
        {
            $licenseCheckStatus = "FAILED"
            # get summary for breakdown
            $summary = & $pathToLicenseChecker $productionFlag --summary
        }        
    }

    if (($action -eq 'generate-attributions')  -Or ($action -eq 'all')) 
    {
        if (-Not $silent) { Write-Host "Generating license attributions file" }
        $licenseFiles = Get-ChildItem -Path .\node_modules\*\LICENSE
        $attributionsList += "This product uses third-party components with the following licenses:`r`n`r`n"
        foreach ($license in $licenseFiles)
        {
            # if (-Not $silent) { Write-Host "Found LICENSE file in: $license" }
            $attributionsList += "="*$($license.Directory.Name).Length + 
                "`r`n$($license.Directory.Name)`r`n"+ "="*$($license.Directory.Name).Length +"`r`n"
            $attributionsList += $(Get-Content -Path $license -Encoding UTF8 -Raw)
            $attributionsList += "`r`n"
        }
    }
    
    $attributionsList | Out-File -FilePath $attributionsOutputFile

    if (-Not $silent)
    {
        if (($action -eq 'find-vulnerabilities') -Or ($action -eq "all"))
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

        if (($action -eq 'check-licenses') -Or ($action -eq "all"))
        {
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
    }

    if ($outputFileVuln)
    {
        $findingsVuln | ConvertTo-Json | Out-File $outputFileVuln -Encoding ASCII
    }

}
catch
{
    if (-Not $silent) { Write-Host "Error occurred: $($_.Exception)" }
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
