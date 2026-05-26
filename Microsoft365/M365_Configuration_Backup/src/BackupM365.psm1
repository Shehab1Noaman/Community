Set-StrictMode -Version Latest

$publicPath = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
$privatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'

if (-not (Test-Path -Path $privatePath)) {
    throw "Required module folder not found: $privatePath"
}

if (-not (Test-Path -Path $publicPath)) {
    throw "Required module folder not found: $publicPath"
}

Get-ChildItem -Path $privatePath -Filter '*.ps1' -File | ForEach-Object {
    . $_.FullName
}

Get-ChildItem -Path $publicPath -Filter '*.ps1' -File | ForEach-Object {
    . $_.FullName
}

$publicFunctions = Get-ChildItem -Path $publicPath -Filter '*.ps1' -File | ForEach-Object {
    $_.BaseName
}

Export-ModuleMember -Function $publicFunctions
