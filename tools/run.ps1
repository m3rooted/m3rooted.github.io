param(
	[string]$Host = "127.0.0.1",
	[switch]$Production,
	[switch]$Help
)

if ($Help) {
	Write-Host "Usage: ./tools/run.ps1 [-Host 127.0.0.1] [-Production]"
	exit 0
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

if ($Production) {
	$env:JEKYLL_ENV = "production"
}

bundle exec jekyll s -l -H $Host
