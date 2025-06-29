<#
.SYNOPSIS
Scans files for potential credentials using customizable keyword patterns.

.DESCRIPTION
Invoke-CredHunt recursively searches through files looking for specified keywords that might indicate exposed credentials. 
It provides detailed context for matches with ANSI-colored output, file statistics, and performance metrics. 
The tool is designed for security professionals to quickly identify potential credential leaks.

.PARAMETER Path
The directory path to search. Defaults to current directory.

.PARAMETER Keywords
Array of keywords to search for. Default: administrator, password, passwd, pwd, creds, credential

.PARAMETER Exclude
File patterns to exclude from search (e.g., *.dll, *.exe).

.PARAMETER Include
File patterns to specifically include in search. By default, all files are searched.

.PARAMETER MaxContext
Maximum context characters to show around matches. Default: 100.

.PARAMETER CaseSensitive
Perform case-sensitive search. Default is case-insensitive.

.PARAMETER NoSummary
Suppress the scan summary report.

.PARAMETER MaxFileSizeMB
Maximum file size to scan in MB. Larger files are skipped. Default: 20.

.EXAMPLE
Invoke-CredHunt
Scans current directory for default credential keywords.

.EXAMPLE
Invoke-CredHunt -Path C:\Projects -Keywords "api_key", "secret_token" -CaseSensitive
Scans C:\Projects for case-sensitive matches of custom keywords.

.EXAMPLE
Invoke-CredHunt -Path D:\ -Exclude *.log, *.bak -MaxFileSizeMB 50
Scans D drive excluding log/backup files, processing files up to 50MB.

.EXAMPLE
Invoke-CredHunt -Path \\server\share -Include *.config, *.env -NoSummary
Scans network share for configuration files only, suppressing the summary.

.EXAMPLE
Invoke-CredHunt -Path /var/log -Keywords "password", "passphrase" -MaxContext 50
Scans Linux log files with custom context size.

.NOTES
Always review findings carefully - false positives are common.
Rotate any credentials found in scan results immediately.
#>
function Invoke-CredHunt {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Path = ".",
        
        [Parameter()]
        [string[]]$Keywords = @("administrator", "password", "passwd", "pwd", "creds", "credential"),
        
        [Parameter()]
        [string[]]$Exclude,
        
        [Parameter()]
        [string[]]$Include,
        
        [Parameter()]
        [int]$MaxContext = 100,
        
        [Parameter()]
        [switch]$CaseSensitive,
        
        [Parameter()]
        [switch]$NoSummary,
        
        [Parameter()]
        [int]$MaxFileSizeMB = 20
    )

    # ANSI color code definitions
    $colorCyan = "$([char]27)[36m"
    $colorYellow = "$([char]27)[33m"
    $colorDarkGray = "$([char]27)[90m"
    $colorRed = "$([char]27)[91m"
    $colorGreen = "$([char]27)[92m"
    $colorMagenta = "$([char]27)[95m"
    $resetColor = "$([char]27)[0m"

    # Escape keywords and build pattern
    $escapedKeywords = $Keywords | ForEach-Object { [regex]::Escape($_) }
    $pattern = $escapedKeywords -join '|'

    # Build file search parameters
    $gciParams = @{
        Path        = $Path
        Recurse     = $true
        File        = $true
        ErrorAction = 'SilentlyContinue'
    }
    
    # Add Include/Exclude only if explicitly provided
    if ($PSBoundParameters.ContainsKey('Include')) { $gciParams['Include'] = $Include }
    if ($PSBoundParameters.ContainsKey('Exclude')) { $gciParams['Exclude'] = $Exclude }

    # Initialize counters
    $fileCounter = 0
    $matchCounter = 0
    $scannedFileCount = 0
    $largeFileSkipCount = 0
    $startTime = Get-Date
    $files = Get-ChildItem @gciParams
    $totalFiles = $files.Count

    # Process files
    foreach ($file in $files) {
        $scannedFileCount++
        
        # Skip large files based on threshold
        if ($file.Length -gt ($MaxFileSizeMB * 1MB)) {
            $largeFileSkipCount++
            continue
        }
        
        # Configure Select-String parameters
        $selectParams = @{
            Path = $file.FullName
            Pattern = $pattern
            AllMatches = $true
            ErrorAction = 'SilentlyContinue'
        }
        
        # Add case sensitivity if requested
        if ($CaseSensitive) {
            $selectParams['CaseSensitive'] = $true
        }
        
        $results = Select-String @selectParams
            
        if ($results) {
            $fileCounter++
            $fileHeader = "`n" + ("="*80) + "`nFILE: $($file.FullName) ($([math]::Round($file.Length/1KB, 2)) KB)`n" + ("="*80)
            Write-Host "${colorCyan}${fileHeader}${resetColor}"
            
            foreach ($result in $results) {
                $matchCounter += $result.Matches.Count
                
                $lineHeader = "LINE $($result.LineNumber):"
                Write-Host "${colorYellow}${lineHeader}${resetColor}"
                
                $lineText = $result.Line
                $lineLength = $lineText.Length
                
                foreach ($match in $result.Matches) {
                    $startIndex = $match.Index
                    $endIndex = $startIndex + $match.Length
                    
                    # Calculate context
                    $contextSize = [Math]::Min($MaxContext, [int]($lineLength/3))
                    $contextStart = [Math]::Max(0, $startIndex - $contextSize)
                    $contextEnd = [Math]::Min($lineLength, $endIndex + $contextSize)
                    $contextLength = $contextEnd - $contextStart
                    
                    $context = $lineText.Substring($contextStart, $contextLength)
                    
                    $prefix = if ($contextStart -gt 0) { "..." } else { "" }
                    $suffix = if ($contextEnd -lt $lineLength) { "..." } else { "" }
                    
                    # Precise match highlighting
                    $highlightedContext = $context -replace [regex]::Escape($match.Value), 
                                                            "${colorRed}$($match.Value)${resetColor}"
                    
                    # Position indicator
                    $positionText = "  -> POS $startIndex ($($match.Length) chars)"
                    Write-Host "${colorDarkGray}${positionText}${resetColor}: ${prefix}${highlightedContext}${suffix}"
                }
            }
        }
    }

    # Display summary
    if (-not $NoSummary) {
        $elapsed = (Get-Date) - $startTime
        $rate = if ($elapsed.TotalSeconds -gt 0) { [math]::Round($scannedFileCount / $elapsed.TotalSeconds, 1) } else { $scannedFileCount }
        
        Write-Host "`n${colorGreen}CREDENTIAL SCAN SUMMARY:${resetColor}"
        Write-Host "  Scanned files       : $scannedFileCount/$totalFiles"
        Write-Host "  Files matched       : $fileCounter"
        Write-Host "  Total matches       : $matchCounter"
        if ($largeFileSkipCount -gt 0) {
            Write-Host "  Large files skipped : $largeFileSkipCount (>${MaxFileSizeMB}MB)"
        }
        Write-Host "  Scan duration       : $([math]::Round($elapsed.TotalSeconds, 2)) seconds"
        Write-Host "  Scan speed          : $rate files/sec"
        Write-Host "  Search path         : $(Resolve-Path $Path)"
        Write-Host "  Keywords            : $($Keywords -join ', ')"
        Write-Host "  Case sensitive      : $($CaseSensitive.IsPresent)"
        Write-Host "  Max file size       : ${MaxFileSizeMB}MB"
        if ($PSBoundParameters.ContainsKey('Include')) { Write-Host "  Included            : $($Include -join ', ')" }
        if ($PSBoundParameters.ContainsKey('Exclude')) { Write-Host "  Excluded            : $($Exclude -join ', ')" }
    }
}
