# Invoke-CredHunt
![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Language: PowerShell](https://img.shields.io/badge/Language-PowerShell-blue)

Invoke-CredHunt is a simple PowerShell script designed to identify potential credential leaks by scanning files for sensitive keywords. It provides security professionals and system administrators with an efficient way to hunt for exposed credentials in file systems, with detailed context highlighting and comprehensive scanning metrics.

# Key Features
- 🔍 Smart Keyword Detection: Searches for credentials using customizable patterns
- 🎨 ANSI Colorized Output: Highlights matches with color-coded context
- ⚡ Performance Optimized: Skips large files and handles exclusions efficiently
- 📊 Detailed Statistics: Provides scan metrics and performance benchmarks 
- 🛠️ Flexible Parameters: Customize search with inclusion/exclusion filters
- 🔐 Security Focused: Case-sensitive option for precise credential hunting

# Usage Examples
```powershell
Invoke-CredHunt
```
Basic Scan (Current Directory)

```powershell
Invoke-CredHunt -Path "C:\Projects" -Keywords API_KEY, SECRET_TOKEN -CaseSensitive
```
Custom Path with Case-Sensitive Search

```powershell
Invoke-CredHunt -Path "C:\Users\Administrator\AppData" -NoSummary -Exclude *.dll,*.exe -Keywords password,administrator -IncludeHidden
```
Scan Including Hidden Files and Directory (*Takes longer)

```powershell
Invoke-CredHunt -Path "\\server\share" -Include *.config, *.env -Exclude *.bak, *.tmp -MaxFileSizeMB 50
```
Scan Network Share with File Filters

# Parameters Reference
| Parameter | Description | Default Value |
| --- | --- | --- |
| `-Path` | Directory path to scan | Current directory (.) |
| `-Keywords` | Keywords to search for | administrator, password, creds, etc. |
| `-Exclude` | File patterns to exclude | None |
| `-Include` | File patterns to specifically include | None (all files) |
| `-MaxContext` | Context characters around matches | 100 |
| `-CaseSensitive` | Enable case-sensitive search | False |
| `-NoSummary` | Suppress scan summary report | False |
| `-IncludeHidden` | Include hidden files and directories | False |
| `-MaxFileSizeMB` | Maximum file size to scan (MB) | 20 |

# Requirements
- PowerShell 5.1+ (Windows) or PowerShell 7+ (Cross-Platform)

# Security Notes
1. Always review findings carefully - false positives are common
2. Immediately rotate any credentials found in scan results
3. Run scans with appropriate permissions only
4. Never store scan results with exposed credentials
5. Use in test environments first to understand behavior

# License
This project is licensed under the GPLv3 License - see the [LICENSE](https://github.com/TacticalGator/Invoke-CredHunt/blob/main/LICENSE) file for details.
> Disclaimer: This tool is for security auditing and educational purposes only. Never use on production systems without proper authorization. The maintainers are not responsible for any misuse or damage caused.
