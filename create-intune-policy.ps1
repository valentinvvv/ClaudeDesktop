# create-intune-policy.ps1
# Creates the Claude Desktop enterprise configuration profile in Intune via Microsoft Graph.
# Requires the Microsoft.Graph.Authentication module only (lightweight — ~2MB).
#
# Usage:
#   .\create-intune-policy.ps1
#
# A browser window will open to sign in. You need:
#   - An Entra ID account with Intune Administrator or Global Administrator role
#   - DeviceManagementConfiguration.ReadWrite.All permission (admin consent on first run)

#Requires -Version 5.1

# --- Module check ---
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Installing Microsoft.Graph.Authentication module..."
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -ErrorAction Stop
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# --- Connect (interactive browser) ---
Write-Host "A browser window will open — sign in with your Intune admin account."
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All" -NoWelcome -WarningAction SilentlyContinue -ErrorAction Stop
Write-Host "Connected as: $((Get-MgContext).Account)"
Write-Host ""

# --- Policy definition ---
$policy = @{
    "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"
    displayName   = "Claude Desktop - Enterprise Policy"
    description   = "Machine-wide registry settings for Claude Desktop. Enables auto-updates, Cowork (secureVmFeaturesEnabled), and desktop extensions."
    omaSettings   = @(
        @{
            "@odata.type" = "#microsoft.graph.omaSettingInteger"
            displayName   = "Claude - Disable Auto Updates"
            description   = "0 = auto-updates enabled"
            omaUri        = "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Claude/disableAutoUpdates"

            value         = 0
        },
        @{
            "@odata.type" = "#microsoft.graph.omaSettingInteger"
            displayName   = "Claude - Auto Updater Enforcement Hours"
            description   = "Max hours before Claude force-restarts to apply a pending update (1-72)"
            omaUri        = "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Claude/autoUpdaterEnforcementHours"

            value         = 72
        },
        @{
            "@odata.type" = "#microsoft.graph.omaSettingInteger"
            displayName   = "Claude - Enable Cowork (secureVmFeaturesEnabled)"
            description   = "1 = Cowork feature enabled. Requires Virtual Machine Platform to be active."
            omaUri        = "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Claude/secureVmFeaturesEnabled"

            value         = 1
        },
        @{
            "@odata.type" = "#microsoft.graph.omaSettingInteger"
            displayName   = "Claude - Enable Desktop Extensions"
            description   = "1 = extensions enabled"
            omaUri        = "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Claude/isDesktopExtensionEnabled"

            value         = 1
        },
        @{
            "@odata.type" = "#microsoft.graph.omaSettingInteger"
            displayName   = "Claude - Enable Extension Directory"
            description   = "1 = extension directory access enabled"
            omaUri        = "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Claude/isDesktopExtensionDirectoryEnabled"

            value         = 1
        },
        @{
            "@odata.type" = "#microsoft.graph.omaSettingInteger"
            displayName   = "Claude - Enable Local Dev MCP"
            description   = "1 = local MCP servers enabled"
            omaUri        = "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Claude/isLocalDevMcpEnabled"

            value         = 1
        },
        @{
            "@odata.type" = "#microsoft.graph.omaSettingInteger"
            displayName   = "Claude - Enable Claude Code for Desktop"
            description   = "1 = Claude Code access enabled in desktop"
            omaUri        = "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Claude/isClaudeCodeForDesktopEnabled"

            value         = 1
        }
    )
}

$body = $policy | ConvertTo-Json -Depth 10
$baseUri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations"

# --- Check for existing profile ---
Write-Host "Checking for existing profile..."
$filterUri = "${baseUri}?`$filter=displayName eq 'Claude Desktop - Enterprise Policy'"
$existing = (Invoke-MgGraphRequest -Method GET -Uri $filterUri).value

if ($existing) {
    $existingId = $existing[0].id
    Write-Host "WARNING: Profile already exists (ID: $existingId)."
    $confirm = Read-Host "Overwrite it? (y/n)"
    if ($confirm -ne 'y') {
        Write-Host "Aborted. No changes made."
        Disconnect-MgGraph | Out-Null
        exit 0
    }
    Write-Host "Updating existing profile..."
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "$baseUri/$existingId" -Body $body -ContentType "application/json" -ErrorAction Stop
        Write-Host "Profile updated. ID: $existingId"
    } catch {
        Write-Host "ERROR: Update failed: $_"
        Disconnect-MgGraph | Out-Null
        exit 1
    }
} else {
    Write-Host "Creating profile..."
    try {
        $result = Invoke-MgGraphRequest -Method POST -Uri $baseUri -Body $body -ContentType "application/json" -ErrorAction Stop
        Write-Host "Profile created. ID: $($result.id)"
    } catch {
        Write-Host "ERROR: Create failed: $_"
        Disconnect-MgGraph | Out-Null
        exit 1
    }
}

Write-Host ""
Write-Host "Done. Go to Devices > Configuration profiles in Intune and assign the profile to your device group."
Disconnect-MgGraph | Out-Null
