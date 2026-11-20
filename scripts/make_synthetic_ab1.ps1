# Generates a synthetic AB1 (ABIF) file from one entry of a multi-FASTA, for checking the
# sequencing preview in the GUI without a real capillary read. Basecalls = the FASTA
# sequence, quality 50 everywhere, one Gaussian peak per base (12 scans apart).
# Name the output so parse_ab1_filename() picks the gene (e.g. *_hsp65.ab1, see
# src/sequencing/ab1_filename.rs). Works with Windows PowerShell 5.1 and pwsh.
#
# Example:
#   ./scripts/make_synthetic_ab1.ps1 -Fasta res/sequences/references/hsp65_TB11_TB12.fasta `
#       -AccessionPrefix 'GCF_002102175.1|' -OutFile target/synthetic_ab1/2026999001_hsp65_gastri_synthetic.ab1
param(
    [Parameter(Mandatory)] [string]$Fasta,
    [Parameter(Mandatory)] [string]$AccessionPrefix,
    [Parameter(Mandatory)] [string]$OutFile
)
$ErrorActionPreference = 'Stop'

# .NET file APIs resolve relative paths against the process directory, not the PowerShell location.
$Fasta = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Fasta)
$OutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)

# --- pull the sequence for the requested accession out of the multi-FASTA ---
$seq = New-Object System.Text.StringBuilder
$inRecord = $false
foreach ($line in [System.IO.File]::ReadLines($Fasta)) {
    if ($line.StartsWith('>')) {
        if ($inRecord) { break }
        $inRecord = $line.Substring(1).StartsWith($AccessionPrefix)
        if ($inRecord) { Write-Host "Using: $line" }
    } elseif ($inRecord) {
        [void]$seq.Append($line.Trim().ToUpperInvariant())
    }
}
$bases = [System.Text.Encoding]::ASCII.GetBytes($seq.ToString())
if ($bases.Length -eq 0) { throw "accession $AccessionPrefix not found in $Fasta" }
$n = $bases.Length

# --- synthetic chromatogram: one Gaussian peak per base, 12 scans apart ---
$spacing = 12; $lead = 20; $sigma = 2.5; $height = 1500
$scans = $lead * 2 + $n * $spacing
$order = 'GATC'                          # FWO_: channel order of DATA 9..12
$traces = @{}
foreach ($c in $order.ToCharArray()) { $traces[$c] = New-Object 'int16[]' $scans }
$ploc = New-Object 'uint16[]' $n
for ($i = 0; $i -lt $n; $i++) {
    $center = $lead + $i * $spacing
    $ploc[$i] = [uint16]$center
    $b = [char]$bases[$i]
    for ($s = [Math]::Max(0, $center - 10); $s -le [Math]::Min($scans - 1, $center + 10); $s++) {
        $v = $height * [Math]::Exp(-[Math]::Pow($s - $center, 2) / (2 * $sigma * $sigma))
        foreach ($c in $order.ToCharArray()) {
            $amp = if ($c -eq $b) { $v } else { $v * 0.04 }   # small background in other channels
            $traces[$c][$s] = [int16][Math]::Min(32767, $traces[$c][$s] + $amp)
        }
    }
}
$qual = New-Object 'byte[]' $n
for ($i = 0; $i -lt $n; $i++) { $qual[$i] = 50 }

# --- big-endian helpers ---
function BE16([int]$v) { $b = [BitConverter]::GetBytes([int16]$v); [Array]::Reverse($b); $b }
function BE16u([int]$v) { $b = [BitConverter]::GetBytes([uint16]$v); [Array]::Reverse($b); $b }
function BE32([int]$v) { $b = [BitConverter]::GetBytes([int32]$v); [Array]::Reverse($b); $b }

# --- tag list: name, number, elemType, elemSize, numElems, payload ---
$tags = New-Object System.Collections.ArrayList
function Add-Tag($name, $num, $type, $esize, $count, [byte[]]$payload) {
    [void]$tags.Add([pscustomobject]@{ Name = $name; Num = $num; Type = $type; ESize = $esize; Count = $count; Data = $payload })
}
foreach ($k in 0..3) {
    $c = $order[$k]
    $ms = New-Object System.IO.MemoryStream
    foreach ($v in $traces[$c]) { $ms.Write((BE16 $v), 0, 2) }
    Add-Tag 'DATA' (9 + $k) 4 2 $scans $ms.ToArray()
}
foreach ($num in 1, 2) {
    Add-Tag 'PBAS' $num 2 1 $n $bases
    Add-Tag 'PCON' $num 2 1 $n $qual
    $ms = New-Object System.IO.MemoryStream
    foreach ($v in $ploc) { $ms.Write((BE16u $v), 0, 2) }
    Add-Tag 'PLOC' $num 4 2 $n $ms.ToArray()
}
Add-Tag 'FWO_' 1 2 1 4 ([System.Text.Encoding]::ASCII.GetBytes($order))
$sample = [System.Text.Encoding]::ASCII.GetBytes('synthetic')
Add-Tag 'SMPL' 1 18 1 ($sample.Length + 1) ([byte[]](,[byte]$sample.Length + $sample))

# --- layout: 128-byte header, then data blocks, then directory ---
$out = New-Object System.IO.MemoryStream
$out.Write((New-Object 'byte[]' 128), 0, 128)
$offsets = @{}
for ($t = 0; $t -lt $tags.Count; $t++) {
    $tag = $tags[$t]
    if ($tag.Data.Length -gt 4) {
        $offsets[$t] = [int]$out.Position
        $out.Write($tag.Data, 0, $tag.Data.Length)
    }
}
$dirOffset = [int]$out.Position
for ($t = 0; $t -lt $tags.Count; $t++) {
    $tag = $tags[$t]
    $out.Write([System.Text.Encoding]::ASCII.GetBytes($tag.Name), 0, 4)
    $out.Write((BE32 $tag.Num), 0, 4)
    $out.Write((BE16 $tag.Type), 0, 2)
    $out.Write((BE16 $tag.ESize), 0, 2)
    $out.Write((BE32 $tag.Count), 0, 4)
    $out.Write((BE32 $tag.Data.Length), 0, 4)
    if ($tag.Data.Length -gt 4) {
        $out.Write((BE32 $offsets[$t]), 0, 4)
    } else {
        $inline = New-Object 'byte[]' 4
        [Array]::Copy($tag.Data, $inline, $tag.Data.Length)
        $out.Write($inline, 0, 4)
    }
    $out.Write((BE32 0), 0, 4)               # data handle
}
$bytes = $out.ToArray()

# --- header: "ABIF", version 101, root dir entry "tdir" ---
$hdr = New-Object System.IO.MemoryStream
$hdr.Write([System.Text.Encoding]::ASCII.GetBytes('ABIF'), 0, 4)
$hdr.Write((BE16 101), 0, 2)
$hdr.Write([System.Text.Encoding]::ASCII.GetBytes('tdir'), 0, 4)
$hdr.Write((BE32 1), 0, 4)
$hdr.Write((BE16 1023), 0, 2)
$hdr.Write((BE16 28), 0, 2)
$hdr.Write((BE32 $tags.Count), 0, 4)          # byte 18
$hdr.Write((BE32 ($tags.Count * 28)), 0, 4)
$hdr.Write((BE32 $dirOffset), 0, 4)           # byte 26
$hdr.Write((BE32 0), 0, 4)
$h = $hdr.ToArray()
[Array]::Copy($h, $bytes, $h.Length)

New-Item -ItemType Directory -Force (Split-Path $OutFile) | Out-Null
[System.IO.File]::WriteAllBytes($OutFile, $bytes)
Write-Host "Wrote $OutFile ($n bases, $scans scans, $($bytes.Length) bytes)"
