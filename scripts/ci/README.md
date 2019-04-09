# Continuous integration

This folder contains scripts for automatic building of `IPASimulator`.

## Azure authentication

To authenticate in Azure PowerShell, see [How to: Use the portal to create an
Azure AD application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal).
That only works for the new Azure Resource Manager, though. We currently use
Classic Azure VM, so we instead created a new user in Azure Active Directory and
used that user to authenticate. Note that immediately after creating the user,
its password expires, so you need to login to [Azure Portal](https://portal.azure.com)
and change the password. Then, use its username as `AZURE_APP_ID` and its
password as `AZURE_KEY` (see script `auth.ps1`). Also, you need to set the user
as co-administrator of the subscription you have the Virtual Machine in.

Note that you have to create new user since Microsoft Live Accounts cannot be
used like this. See [Add-AzureRmAccount : Sequence contains no elements](https://stackoverflow.com/a/41608514)
on StackOverflow.
