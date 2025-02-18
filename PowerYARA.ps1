param (
    [string]$FilePath,
    [string]$RuleName = $null,
    [string]$OutputPath = $null,
    [switch]$IncludeImports
)

if (-not (Test-Path $FilePath)) {
    Write-Host "Error: File not found!" -ForegroundColor Red
    exit
}

$FileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
$RuleName = if ($RuleName) { $RuleName } else { $FileName }
$FileHash = (Get-FileHash -Algorithm MD5 -Path $FilePath).Hash

# Extract strings
$Strings = Get-Content $FilePath -Encoding Byte | 
    ForEach-Object { ($_ -band 127) -as [char] } -join "" |
    Select-String -Pattern "[\x20-\x7E]{4,}" -AllMatches | 
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# Generate YARA rule
$YaraRule = @"
rule $RuleName
{
    meta:
        author = "AutoYaraGen"
        date = "$(Get-Date -Format yyyy-MM-dd)"
        description = "Auto-generated YARA rule for $FileName"
        hash = "$FileHash"
        
    strings:
$(($Strings | Select-Object -First 5 | ForEach-Object { "        $" + ($_ -replace '\W', '_') + ' = "' + $_ + '" fullword ascii' }) -join "`n")

    condition:
        any of them
}
"@

# Output to console or file
if ($OutputPath) {
    $YaraRule | Out-File -Encoding utf8 $OutputPath
    Write-Host "YARA rule saved to $OutputPath" -ForegroundColor Green
} else {
    Write-Host $YaraRule
}
