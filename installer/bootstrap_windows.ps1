#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Command {
	param(
		[string]$Name
	)
	try { return [bool](Get-Command -Name $Name -ErrorAction Stop) } catch { return $false }
}

function Test-Admin {
	$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
	$wp = New-Object Security.Principal.WindowsPrincipal($wi)
	return $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-PythonInterpreter {
	# Prefer the py launcher for Python 3.12 specifically
	if (Test-Command 'py') {
		try {
			$null = & py -3.12 -V 2>$null
			if ($LASTEXITCODE -eq 0) { return @{ Path = 'py'; Args = '-3.12' } }
		} catch {}
		try {
			$null = & py -3 -V 2>$null
			if ($LASTEXITCODE -eq 0) { return @{ Path = 'py'; Args = '-3' } }
		} catch {}
	}
	# Fallback to python on PATH
	if (Test-Command 'python') {
		try { $v = & python -V 2>$null; if ($LASTEXITCODE -eq 0) { return @{ Path = 'python'; Args = '' } } } catch {}
	}
	return $null
}

function Get-PythonVersionString($Path, $Args) {
	try {
		if ($null -ne $Args -and $Args -ne '') { return & $Path $Args -V 2>$null }
		else { return & $Path -V 2>$null }
	} catch { return $null }
}

function Is-ExactPython3123Present {
	# Check py -3.12 first
	if (Test-Command 'py') {
		$vs = Get-PythonVersionString 'py' '-3.12'
		if ($vs -and $vs -match 'Python\s+3\.12\.3') { return $true }
	}
	# Fallback to python on PATH
	if (Test-Command 'python') {
		$vs = Get-PythonVersionString 'python' ''
		if ($vs -and $vs -match 'Python\s+3\.12\.3') { return $true }
	}
	return $false
}

function Install-Python-WithWinget {
	Write-Host 'Attempting to install Python via winget (Python.Python.3.12 @ 3.12.3)...'
	$wingetArgs = @('install','-e','--id','Python.Python.3.12','--version','3.12.3','--accept-package-agreements','--accept-source-agreements')
	& winget @wingetArgs
	return $LASTEXITCODE -eq 0
}

function Install-Python-WithChoco {
	if (-not (Test-Admin)) {
		Write-Host 'Skipping Chocolatey install (admin rights required).'
		return $false
	}
	Write-Host 'Attempting to install Python via Chocolatey (python==3.12.3)...'
	& choco install -y python --version=3.12.3
	return $LASTEXITCODE -eq 0
}

function Install-Python-DirectDownload {
	Write-Host 'Attempting direct download from python.org...'
	$ver = '3.12.3'
	$arch = $env:PROCESSOR_ARCHITECTURE
	$plat = if ($arch -eq 'ARM64') { 'arm64' } elseif ($arch -eq 'AMD64') { 'amd64' } else { 'amd64' }
	$uri = "https://www.python.org/ftp/python/$ver/python-$ver-$plat.exe"
	$out = Join-Path $env:TEMP "python-$ver-$plat.exe"
	Write-Host "Downloading $uri to $out"
	Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $out
	# Silent install flags
	$admin = Test-Admin
	if ($admin) {
		$installerArgs = @('/quiet','InstallAllUsers=1','PrependPath=1','Include_launcher=1','Include_test=0')
	} else {
		# Per-user install if not admin
		$installerArgs = @('/quiet','InstallAllUsers=0','PrependPath=1','Include_launcher=1','Include_test=0')
	}
	Write-Host 'Starting Python installer (silent)...'
	$proc = Start-Process -FilePath $out -ArgumentList $installerArgs -PassThru -Wait
	return ($proc.ExitCode -eq 0)
}

function Ensure-Python-Installed3123 {
	if (Is-ExactPython3123Present) { return $true }
	if (Test-Command 'winget') {
		if (Install-Python-WithWinget) { if (Is-ExactPython3123Present) { return $true } }
	}
	if (Test-Command 'choco') {
		if (Install-Python-WithChoco) { if (Is-ExactPython3123Present) { return $true } }
	}
	if (Install-Python-DirectDownload) { if (Is-ExactPython3123Present) { return $true } }
	return $false
}

# Main
Write-Host '=== Employee Monitoring System - Windows Bootstrap ==='
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $here
try {
	if (-not (Ensure-Python-Installed3123)) {
		throw 'Failed to install Python 3.12.3 automatically. Please install Python 3.12.3 and re-run.'
	}
	# Prefer py -3.12 to ensure exact version is used
	$interp = if (Test-Command 'py') { @{ Path = 'py'; Args = '-3.12' } } else { Get-PythonInterpreter }
	if (-not $interp) { throw 'Python appears installed but not on PATH.' }
	$scriptPath = Join-Path $here '..\installer\install.py'
	$scriptPath = [System.IO.Path]::GetFullPath($scriptPath)
	Write-Host "Launching installer with: $($interp.Path) $($interp.Args) $scriptPath"
	if ($interp.Args) {
		& $interp.Path $interp.Args $scriptPath
	} else {
		& $interp.Path $scriptPath
	}
	exit $LASTEXITCODE
}
finally {
	Pop-Location
}
