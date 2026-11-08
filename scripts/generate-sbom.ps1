<#
.SYNOPSIS
  Generate a CycloneDX 1.5 SBOM for the workspace from `cargo metadata`.

.DESCRIPTION
  Dependency-free (no cargo plugin required). Emits every resolved package as a
  CycloneDX `library` component with a `pkg:cargo` purl and license expression.
  The workspace's own crates are emitted as the top-level application component.

  Intended for release artifacts / CI. The output is not committed (see .gitignore).

.PARAMETER Output
  Destination file. Defaults to `sbom.cdx.json` in the repo root.

.EXAMPLE
  ./scripts/generate-sbom.ps1 -Output dist/sbom.cdx.json
#>
[CmdletBinding()]
param(
    [string]$Output = "sbom.cdx.json"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $meta = cargo metadata --format-version 1 --locked | ConvertFrom-Json
} finally {
    Pop-Location
}

# This is a virtual workspace (no root package), so pick the GUI crate's version.
$rootPkg = $meta.packages | Where-Object { $_.name -eq "selflock-gui" }
if (-not $rootPkg) {
    $rootPkg = $meta.packages |
        Where-Object { $meta.workspace_members -contains $_.id } |
        Select-Object -First 1
}
$version = if ($rootPkg) { $rootPkg.version } else { "0.0.0" }

function Get-Purl($p) {
    if ($p.name -and $p.version) { "pkg:cargo/{0}@{1}" -f $p.name, $p.version } else { $null }
}

$components = foreach ($p in $meta.packages) {
    $purl = Get-Purl $p
    $component = [ordered]@{
        type    = "library"
        name    = $p.name
        version = $p.version
    }
    if ($purl) { $component["bom-ref"] = $purl; $component["purl"] = $purl }
    if ($p.license) { $component["licenses"] = @(@{ expression = $p.license }) }
    $component
}

$serial = "urn:uuid:{0}" -f ([guid]::NewGuid().ToString())

$bom = [ordered]@{
    bomFormat    = "CycloneDX"
    specVersion  = "1.5"
    serialNumber = $serial
    version      = 1
    metadata     = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        tools     = [ordered]@{
            components = @(
                [ordered]@{
                    type    = "application"
                    name    = "generate-sbom"
                    version = "1.0.0"
                }
            )
        }
        component = [ordered]@{
            type    = "application"
            name    = "SelfLock"
            version = $version
        }
    }
    components   = @($components)
}

$dir = Split-Path -Parent $Output
if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

$json = $bom | ConvertTo-Json -Depth 12
Set-Content -LiteralPath $Output -Value $json -Encoding UTF8
Write-Host ("Wrote {0} ({1} components, {2})" -f $Output, $components.Count, $version)
