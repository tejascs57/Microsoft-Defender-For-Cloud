param(
    [Parameter(Mandatory=$true)]$ResourceGroup,
    [Parameter(Mandatory=$true)]$SubscriptionId,
    [Parameter(Mandatory=$true)]$TenantId,
    [Parameter(Mandatory=$true)]$ClientId,
    [Parameter(Mandatory=$true)]$ClientSecret,
    [Parameter(Mandatory=$true)]$TeamName
)

$failureCount = 0
$successCount = 0
$vmSuccessCount = 0
$arcSuccessCount = 0
$vmCount = 0
$arcCount = 0
$vmResponseMachines = $null
$arcResponseMachines = $null

#Installing & Importing Az module.
Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
Import-Module -Name Az.Resources -Force

Install-Module -Name Microsoft.PowerShell.TextUtility -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
Import-Module -Name Microsoft.PowerShell.TextUtility -Force

# Authenticate to Azure
$SecureStringPwd = $ClientSecret | ConvertTo-SecureString -AsPlainText -Force
$pscredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $SecureStringPwd
Connect-AzAccount -ServicePrincipal -Credential $pscredential -TenantId $TenantId
Set-AzContext -Subscription $SubscriptionId

# Get token
$accessToken = Get-AzAccessToken | Select-Object -ExpandProperty token
$expireson = Get-AzAccessToken | Select-Object -ExpandProperty expireson | Select-Object -ExpandProperty LocalDateTime

# Get all virtual machines and ARC machines in the resource group
try
{
    $vmUrl = "https://management.azure.com/subscriptions/" + $SubscriptionId + "/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01"
    do{
        $vmResponse = Invoke-RestMethod -Method Get -Uri $vmUrl -Headers @{Authorization = "Bearer $accessToken"}
        Write-Host $vmResponse.value
        $vmResponseMachines += $vmResponse.value
        write-host $vmUrl
        $vmUrl = $vmResponse.nextLink
    } while (![string]::IsNullOrEmpty($vmUrl))
    
    $arcUrl = "https://management.azure.com/subscriptions/" + $SubscriptionId + "/resourceGroups/$ResourceGroup/providers/Microsoft.HybridCompute/machines?api-version=2022-12-27"
    do{
        $arcResponse = Invoke-RestMethod -Method Get -Uri $arcUrl -Headers @{Authorization = "Bearer $accessToken"}
        Write-Host $arcResponse.value
        $arcResponseMachines += $arcResponse.value
        write-host $arcUrl
        $arcUrl = $arcResponse.nextLink
    } while (![string]::IsNullOrEmpty($arcUrl))
}
catch 
{
    Write-Host "Failed to Get resources! " -ForegroundColor Red
    Write-Host "Response StatusCode:" $_.Exception.Response.StatusCode.value__  -ForegroundColor Red
    Write-Host "Response StatusDescription:" $_.Exception.Response.StatusDescription -ForegroundColor Red
    Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
}

# Finished fetching machines, display found machines:
Write-Host "Found the following resources:" -ForegroundColor Green
Write-Host "-----------------------------------------------------------------------"
write-host "Virtual Machines:"

if ([string]::IsNullOrEmpty($vmResponseMachines)) {
    Write-Host "0 :  Virtual Machines found"
} else {

    $count = 0
    foreach ($machine in $vmResponseMachines) {
        $count++
        Write-Host $count ": " ($machine.name)
        $vmCount = $count
    }
}

Write-Host "-----------------------------------------------------------------------"
Write-Host "ARC Machines:"

if ([string]::IsNullOrEmpty($arcResponseMachines)) {
    Write-Host "0 :  ARC Machines found"
} else {
    $count = 0
    foreach ($machine in $arcResponseMachines) {
        $count++
        Write-Host $count ": " ($machine.name)
        $arcCount = $count
    }
}
Write-Host "-----------------------------------------------------------------------"
write-host "`n"

Write-Host "Pricing Plan details for all the resources"

# Check if there are no virtual machines
if ($null -eq $vmResponseMachines) {
    Write-Host "No virtual machines found."
}
else {
    # Loop through each VM and output its subplan
    foreach ($vm in $vmResponseMachines) {
        $vmName = $vm.name

        # Construct the API endpoint URL for fetching pricing information for VM
        $vmPricingApiUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$vmName/providers/Microsoft.Security/pricings/VirtualMachines?api-version=2024-01-01"

        # Make the GET request to fetch pricing information for VM
        try {
            $vmPricingResponse = Invoke-RestMethod -Uri $vmPricingApiUrl -Method Get -Headers @{Authorization = "Bearer $accessToken"}
            $vmSubPlan = $vmPricingResponse.properties.subPlan

            if ([string]::IsNullOrEmpty($vmSubPlan)) {
                $vmSubPlan = "No Plan"
            }

            Write-Host "SubPlan for VM ${vmName}: ${vmSubPlan}"
        } 
        catch {
            Write-Host "Failed to fetch pricing information for VM ${vmName}"
            Write-Host "Error: $($_.Exception.Message)"
        }
    }
}

# Check if there are no Azure Arc-enabled servers
if ($null -eq $arcResponseMachines) {
    Write-Host "No Azure Arc-enabled servers found."
}
else {
    Write-Host "Pricing Plan details for all the resources"
    Write-Host "-----------------------------------------------------------------------"

    # Loop through each Azure Arc-enabled server and output its subplan
    foreach ($arc in $arcResponseMachines) {
        $arcName = $arc.name

        # Construct the API endpoint URL for fetching pricing information for Arc machine
        $arcPricingApiUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.HybridCompute/machines/$arcName/providers/Microsoft.Security/pricings?api-version=2024-01-01"

        # Make the GET request to fetch pricing information for Arc machine
        try {
            $arcPricingResponse = Invoke-RestMethod -Uri $arcPricingApiUrl -Method Get -Headers @{Authorization = "Bearer $accessToken"}
            
            # Check if properties exist and if subPlan is not null or empty
            if ($arcPricingResponse.value -and $arcPricingResponse.value.Count -gt 0) {
                foreach ($value in $arcPricingResponse.value) {
                    if ($value.properties -and -not [string]::IsNullOrEmpty($value.properties.subPlan)) {
                        $arcSubPlan = $value.properties.subPlan
                    } else {
                        $arcSubPlan = "No Plan"
                    }
                    Write-Host "SubPlan for Azure Arc machine ${arcName}: ${arcSubPlan}"
                }
            } else {
                Write-Host "No pricing plan information found for Azure Arc machine ${arcName}"
            }
        } 
        catch {
            Write-Host "Failed to fetch pricing information for Azure Arc machine ${arcName}"
            Write-Host "Error: $($_.Exception.Message)"
            Write-Host "Request URL: $arcPricingApiUrl"
            Write-Host "Response Content: $_.Exception.Response.GetResponseStream()"
        }
    }
}
