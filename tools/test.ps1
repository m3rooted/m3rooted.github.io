param(
	[string]$Config = "_config.yml",
	[switch]$Help
)

if ($Help) {
	Write-Host "Build and test the site content"
	Write-Host "Usage: ./tools/test.ps1 [-Config _config.yml]"
	exit 0
}

$siteDir = "_site"
$baseurl = ""

function Get-BaseurlFromConfig {
	param([string]$ConfigList)

	$configs = $ConfigList.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
	[array]::Reverse($configs)

	foreach ($cfg in $configs) {
		if (-not (Test-Path $cfg)) {
			continue
		}

		foreach ($line in Get-Content $cfg) {
			if ($line -match '^\s*baseurl\s*:\s*(.+)$') {
				$value = $Matches[1] -replace '#.*$', ''
				$value = $value.Trim()
				$value = $value.Trim("'")
				$value = $value.Trim('"')
				if ($value) {
					return $value
				}
			}
		}
	}

	return ""
}

# Add common Ruby install locations if they exist but are not in PATH yet.
$rubyBins = @(
	"C:\Ruby33-x64\bin",
	"C:\Ruby34-x64\bin",
	"C:\Ruby32-x64\bin"
)

foreach ($bin in $rubyBins) {
	if ((Test-Path $bin) -and ($env:Path -notlike "*$bin*")) {
		$env:Path = "$bin;$env:Path"
	}
}

if (-not (Get-Command bundle -ErrorAction SilentlyContinue)) {
	Write-Error "Cannot find 'bundle'. Install Ruby + Bundler first, then retry."
	exit 1
}

if (Test-Path $siteDir) {
	Remove-Item -Recurse -Force $siteDir
}

$baseurl = Get-BaseurlFromConfig -ConfigList $Config

$env:JEKYLL_ENV = "production"
bundle exec jekyll b -d "$siteDir$baseurl" -c $Config

bundle exec htmlproofer $siteDir `
	--disable-external `
	--ignore-urls "/^http:\/\/127.0.0.1/,/^http:\/\/0.0.0.0/,/^http:\/\/localhost/"
