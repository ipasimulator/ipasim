./scripts/ci/auth.ps1
Stop-AzureRmVM -ResourceGroupName "ipasim" -Name "ipasim-build" -Force -Verbose
