./scripts/ci/auth.ps1
Stop-AzureVM -ServiceName "ipasim" -Name "ipasim-build" -Force -Verbose
