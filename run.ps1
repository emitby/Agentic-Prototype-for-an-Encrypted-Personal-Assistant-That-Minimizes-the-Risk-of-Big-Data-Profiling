# Personal assistant launcher (Windows PowerShell).
#
# Always start things through this script: it keeps Python's bytecode cache, the
# Playwright browser and temporary files INSIDE the project folder (.cache\), as CLAUDE.md requires.
#
#   .\run.ps1 init                                   create the encrypted vault
#   .\run.ps1 chat [--verbose]                       unlock and chat (needs ANTHROPIC_API_KEY)
#   .\run.ps1 test                                   offline test suite
#   .\run.ps1 scenarios [--live --max-cost 5]        harness scenarios (simulated by default)
#   .\run.ps1 eval [--live --trials 3 --max-cost 8]  evals: red-team, supply cross-check, 16 scorers
#   .\run.ps1 install-browser                        Chromium for the PDF guide, into .cache\
#   .\run.ps1 guide                                  docs\how-it-works.pdf
param([Parameter(Position = 0)][string]$Command = "help",
      [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)

$Root = $PSScriptRoot
$Py = Join-Path $Root ".venv\Scripts\python.exe"
$env:PYTHONPYCACHEPREFIX = Join-Path $Root ".cache\pycache"
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $Root ".cache\ms-playwright"
$Tmp = Join-Path $Root ".cache\tmp"
New-Item -ItemType Directory -Force $Tmp | Out-Null
$env:TEMP = $Tmp
$env:TMP = $Tmp
Set-Location $Root

switch ($Command) {
    "init"            { & $Py -m assistant.cli --init @Rest }
    "chat"            { & $Py -m assistant.cli @Rest }
    "test"            { & $Py -m pytest -q @Rest }
    "scenarios"       { & $Py -m assistant.harness.run_scenarios @Rest }
    "eval"            { & $Py -m evals.run_evals @Rest }
    "install-browser" { & $Py -m playwright install chromium }
    "guide"           { & $Py -m assistant.guide --from-launcher @Rest }
    default           { Get-Content (Join-Path $Root "run.ps1") -TotalCount 12 }
}
exit $LASTEXITCODE
