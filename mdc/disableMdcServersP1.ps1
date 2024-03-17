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
Write-Host "Logging in and authenticating using Service Principal"
$SecureStringPwd = $ClientSecret | ConvertTo-SecureString -AsPlainText -Force
$pscredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $SecureStringPwd
Connect-AzAccount -ServicePrincipal -Credential $pscredential -Tenant $TenantId
Set-AzContext -Subscription $SubscriptionId

Write-Host $ClientId

# Get token
$accessToken = Get-AzAccessToken | Select-Object -ExpandProperty token
$expireson = Get-AzAccessToken | Select-Object -ExpandProperty expireson | Select-Object -ExpandProperty LocalDateTime

Write-Host $accessToken
Write-Host $expireson

# Define variables for authentication and resource group
Write-Host $SubscriptionId
Write-Host $ResourceGroup

$mode = "tag"

if ($mode.ToLower() -eq "rg") {
try
{
    # Get all virtual machines, VMSSs, and ARC machines in the resource group
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

} elseif ($mode.ToLower() -eq "tag") {
    # Fetch resources with a given tagName and tagValue
    $tagName = "environment"
    $tagValue = "UAT"
	
	try
	{
		# Get all virtual machines, VMSSs, and ARC machines in the resource group based on the given tag
		$vmUrl = "https://management.azure.com/subscriptions/" + $SubscriptionId + "/resources?`$filter=resourceType eq 'Microsoft.Compute/virtualMachines'&api-version=2021-04-01"
		do{
			$vmResponse = Invoke-RestMethod -Method Get -Uri $vmUrl -Headers @{Authorization = "Bearer $accessToken"}
			$vmResponseMachines += $vmResponse.value | where {$_.tags.$tagName -eq $tagValue}
			$vmUrl = $vmResponse.nextLink
		} while (![string]::IsNullOrEmpty($vmUrl))
		
		
		$arcUrl = "https://management.azure.com/subscriptions/" + $SubscriptionId + "/resources?`$filter=resourceType eq 'Microsoft.HybridCompute/machines'&api-version=2023-07-01"
		do{
			$arcResponse += Invoke-RestMethod -Method Get -Uri $arcUrl -Headers @{Authorization = "Bearer $accessToken"}
			$arcResponseMachines = $arcResponse.value | where {$_.tags.$tagName -eq $tagValue}
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
} else {
    Write-Host "Entered invalid mode. Exiting script."
	exit 1;
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


#choosing 'Free' to disable the machines with 'P1' subplan
$PricingTier = 'Free'


# Loop through each machine and update the pricing configuration
# write-host "`n"
Write-Host "-------------------------"
Write-Host "Setting Virtual Machines:"
Write-Host "-------------------------"
if ([string]::IsNullOrEmpty($vmResponseMachines)) {
    Write-Host "No virtual machines to update the pricing"
} else {
    foreach ($machine in $vmResponseMachines) {
	# Check if need to renew the token	
    $currentTime = Get-Date
    
    Write-host "Token expires on: $expireson - currentTime: $currentTime"
    if ((get-date $currentTime) -ge (get-date $expireson)) {
		Start-Sleep -Seconds 2
        Write-host "Token expired - refreshing token:"
        $accessToken = Get-AzAccessToken | Select-Object -ExpandProperty token
        $expireson = Get-AzAccessToken | Select-Object -ExpandProperty expireson | Select-Object -ExpandProperty LocalDateTime

        Write-host "New token expires on: $expireson - currentTime: $currentTime - New Token is: $accessToken"
    }
	
    $pricingUrl = "https://management.azure.com$($machine.id)/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01"
    if($PricingTier.ToLower() -eq "free")
	{
		Write-Host "Disabling the Pricing Tier"
		$pricingBody = @{
			"properties" = @{
				"pricingTier" = $PricingTier
			}
		}
	} else 
	{
		# Write-Host "Enabling P1 Pricing Tier"
		$subplan = "P1"
		$pricingBody = @{
			"properties" = @{
				"pricingTier" = $PricingTier
				"subPlan" = $subplan
			}
		}
	}
	Write-Host "Updating pricing configuration for '$($machine.name)':"
	try 
	{
		$pricingResponse = Invoke-RestMethod -Method Put -Uri $pricingUrl -Headers @{Authorization = "Bearer $accessToken"} -Body ($pricingBody | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 120
		Write-Host "Successfully updated pricing configuration for $($machine.name)" -ForegroundColor Green
		$successCount++
		$vmSuccessCount++
	}
	catch {
		$failureCount++
		Write-Host "Failed to update pricing configuration for $($machine.name)" -ForegroundColor Red
		Write-Host "Response StatusCode:" $_.Exception.Response.StatusCode.value__  -ForegroundColor Red
		Write-Host "Response StatusDescription:" $_.Exception.Response.StatusDescription -ForegroundColor Red
		Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	}
	write-host "`n"
	Start-Sleep -Seconds 0.3
}
}

Write-Host "---------------------"
Write-Host "Setting ARC Machine:"
Write-Host "---------------------"
if ([string]::IsNullOrEmpty($arcResponseMachines)) {
    Write-Host "0 :  ARC machines found to update the pricing"
} else {
    Write-Host "Setting ARC Machine:"

    foreach ($machine in $arcResponseMachines) {
	# Check if need to renew the token
    $currentTime = Get-Date
    
    Write-host "Token expires on: $expireson - currentTime: $currentTime"
    if ((get-date $currentTime) -ge (get-date $expireson)) {
		Start-Sleep -Seconds 2
        Write-host "Token expired - refreshing token:"
        $accessToken = Get-AzAccessToken | Select-Object -ExpandProperty token
        $expireson = Get-AzAccessToken | Select-Object -ExpandProperty expireson | Select-Object -ExpandProperty LocalDateTime

        Write-host "New token expires on: $expireson - currentTime: $currentTime - New Token is: $accessToken"
    }
	
    $pricingUrl = "https://management.azure.com$($machine.id)/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01"
    if($PricingTier.ToLower() -eq "free")
	{
		$pricingBody = @{
			"properties" = @{
				"pricingTier" = $PricingTier
			}
		}
	} else 
	{
		$subplan = "P1"
		$pricingBody = @{
			"properties" = @{
				"pricingTier" = $PricingTier
				"subPlan" = $subplan
			}
		}
	}
	Write-Host "Updating pricing configuration for '$($machine.name)':"
	try 
	{
		$pricingResponse = Invoke-RestMethod -Method Put -Uri $pricingUrl -Headers @{Authorization = "Bearer $accessToken"} -Body ($pricingBody | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 120
		Write-Host "Successfully updated pricing configuration for $($machine.name)" -ForegroundColor Green
		$successCount++
		$arcSuccessCount++
	}
	catch {
		$failureCount++
		Write-Host "Failed to update pricing configuration for $($machine.name)" -ForegroundColor Red
		Write-Host "Response StatusCode:" $_.Exception.Response.StatusCode.value__  -ForegroundColor Red
		Write-Host "Response StatusDescription:" $_.Exception.Response.StatusDescription -ForegroundColor Red
		Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	}
	write-host "`n"
	Start-Sleep -Seconds 0.3
}
}



Write-Host "-----------------------------------------------------------------------"
Write-Host "-----------------------------------------------------------------------"
write-host "`n"
# Write a conclusion of all what the script did
Write-Host "Summary of Pricing API results:"
Write-Host "-------------------"
Write-Host "Found Virtual Machines count:" $vmCount
Write-Host "Successfully set Virtual Machines count:" $vmSuccessCount -ForegroundColor Green
Write-Host "Failed setting Virtual Machines count:" $($vmCount - $vmSuccessCount) -ForegroundColor $(if ($($vmCount - $vmSuccessCount) -gt 0) {'Red'} else {'Green'})
write-host "`n"
Write-Host "Found Virtual Machine Scale Sets count:" $vmssCount
Write-Host "Successfully set Virtual Machine Scale Sets result:" $vmssSuccessCount -ForegroundColor Green
Write-Host "Failed setting Virtual Machine Scale Sets count:" $($vmssCount - $vmssSuccessCount) -ForegroundColor $(if ($($vmssCount - $vmssSuccessCount) -gt 0) {'Red'} else {'Green'})
write-host "`n"
Write-Host "Found ARC machines count:" $arcCount
Write-Host "Successfully set ARC Machines count:" $arcSuccessCount -ForegroundColor Gray #
Write-Host "Failed setting ARC Machines count:" $($arcCount - $arcSuccessCount) -ForegroundColor $(if ($($arcCount - $arcSuccessCount) -gt 0) {'Red'} else {'Green'})
write-host "`n"
Write-Host "-------------------"
Write-Host "Overall"
Write-Host "Successfully set resources: $successCount" -ForegroundColor Green
Write-Host "Failures setting resources: $failureCount" -ForegroundColor $(if ($failureCount -gt 0) {'Red'} else {'Green'})


Write-Host "-----------------------------------------------------------------------"
write-host "`n"
Write-Host "Outputting the subplan"

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








