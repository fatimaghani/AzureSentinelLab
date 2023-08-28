# Azure Sentinel Lab: Mapping Failed RDP Logins

## Introduction
In this lab, we will set up Azure Sentinel (SIEM) and connect it to a live virtual machine acting as a honey pot. We will observe live attacks (RDP Brute Force) from all around the world. We will use a custom PowerShell script to look up the attackers Geolocation information and plot it on the Azure Sentinel Map.

## Prerequisites

The Powershell script in this repository is responsible for parsing out Windows Event Log information for failed RDP attacks and using a third party API [ipgeolocation.io](https://ipgeolocation.io/) to collect geographic information about the attackers location. You will `sign up` at ipgeolocation to get your `own` API key to load into the PowerShell script. 

<details>
 <summary><h3> 📜 PowerShell Script </h3></summary> 
 
```powershell 
# Get API key from here: https://ipgeolocation.io/
$API_KEY      = "d4600b4efdef42b39828f5155041a457"
$LOGFILE_NAME = "failed_rdp.log"
$LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"

# This filter will be used to filter failed RDP events from Windows Event Viewer
$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@

<#
    This function creates a bunch of sample log files that will be used to train the
    Extract feature in Log Analytics workspace. If you don't have enough log files to
    "train" it, it will fail to extract certain fields for some reason -_-.
    We can avoid including these fake records on our map by filtering out all logs with
    a destination host of "samplehost"
#>
Function write-Sample-Log() {
    "latitude:47.91542,longitude:-120.60306,destinationhost:samplehost,username:fakeuser,sourcehost:24.16.97.222,state:Washington,country:United States,label:United States - 24.16.97.222,timestamp:2021-10-26 03:28:29" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-22.90906,longitude:-47.06455,destinationhost:samplehost,username:lnwbaq,sourcehost:20.195.228.49,state:Sao Paulo,country:Brazil,label:Brazil - 20.195.228.49,timestamp:2021-10-26 05:46:20" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37022,longitude:4.89517,destinationhost:samplehost,username:CSNYDER,sourcehost:89.248.165.74,state:North Holland,country:Netherlands,label:Netherlands - 89.248.165.74,timestamp:2021-10-26 06:12:56" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:40.71455,longitude:-74.00714,destinationhost:samplehost,username:ADMINISTRATOR,sourcehost:72.45.247.218,state:New York,country:United States,label:United States - 72.45.247.218,timestamp:2021-10-26 10:44:07" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:33.99762,longitude:-6.84737,destinationhost:samplehost,username:AZUREUSER,sourcehost:102.50.242.216,state:Rabat-Salé-Kénitra,country:Morocco,label:Morocco - 102.50.242.216,timestamp:2021-10-26 11:03:13" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-5.32558,longitude:100.28595,destinationhost:samplehost,username:Test,sourcehost:42.1.62.34,state:Penang,country:Malaysia,label:Malaysia - 42.1.62.34,timestamp:2021-10-26 11:04:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:41.05722,longitude:28.84926,destinationhost:samplehost,username:AZUREUSER,sourcehost:176.235.196.111,state:Istanbul,country:Turkey,label:Turkey - 176.235.196.111,timestamp:2021-10-26 11:50:47" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:55.87925,longitude:37.54691,destinationhost:samplehost,username:Test,sourcehost:87.251.67.98,state:null,country:Russia,label:Russia - 87.251.67.98,timestamp:2021-10-26 12:13:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37018,longitude:4.87324,destinationhost:samplehost,username:AZUREUSER,sourcehost:20.86.161.127,state:North Holland,country:Netherlands,label:Netherlands - 20.86.161.127,timestamp:2021-10-26 12:33:46" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:17.49163,longitude:-88.18704,destinationhost:samplehost,username:Test,sourcehost:45.227.254.8,state:null,country:Belize,label:Belize - 45.227.254.8,timestamp:2021-10-26 13:13:25" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-55.88802,longitude:37.65136,destinationhost:samplehost,username:Test,sourcehost:94.232.47.130,state:Central Federal District,country:Russia,label:Russia - 94.232.47.130,timestamp:2021-10-26 14:25:33" | Out-File $LOGFILE_PATH -Append -Encoding utf8
}

# This block of code will create the log file if it doesn't already exist
if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
    write-Sample-Log
}

# Infinite Loop that keeps checking the Event Viewer logs.
while ($true)
{
    
    Start-Sleep -Seconds 1
    # This retrieves events from Windows EVent Viewer based on the filter
    $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue
    if ($Error) {
        #Write-Host "No Failed Logons found. Re-run script when a login has failed."
    }

    # Step through each event collected, get geolocation
    #    for the IP Address, and add new events to the custom log
    foreach ($event in $events) {


        # $event.properties[19] is the source IP address of the failed logon
        # This if-statement will proceed if the IP address exists (>= 5 is arbitrary, just saying if it's not empty)
        if ($event.properties[19].Value.Length -ge 5) {

            # Pick out fields from the event. These will be inserted into our new custom log
            $timestamp = $event.TimeCreated
            $year = $event.TimeCreated.Year

            $month = $event.TimeCreated.Month
            if ("$($event.TimeCreated.Month)".Length -eq 1) {
                $month = "0$($event.TimeCreated.Month)"
            }

            $day = $event.TimeCreated.Day
            if ("$($event.TimeCreated.Day)".Length -eq 1) {
                $day = "0$($event.TimeCreated.Day)"
            }
            
            $hour = $event.TimeCreated.Hour
            if ("$($event.TimeCreated.Hour)".Length -eq 1) {
                $hour = "0$($event.TimeCreated.Hour)"
            }

            $minute = $event.TimeCreated.Minute
            if ("$($event.TimeCreated.Minute)".Length -eq 1) {
                $minute = "0$($event.TimeCreated.Minute)"
            }


            $second = $event.TimeCreated.Second
            if ("$($event.TimeCreated.Second)".Length -eq 1) {
                $second = "0$($event.TimeCreated.Second)"
            }

            $timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"
            $eventId = $event.Id
            $destinationHost = $event.MachineName# Workstation Name (Destination)
            $username = $event.properties[5].Value # Account Name (Attempted Logon)
            $sourceHost = $event.properties[11].Value # Workstation Name (Source)
            $sourceIp = $event.properties[19].Value # IP Address
        

            # Get the current contents of the Log file!
            $log_contents = Get-Content -Path $LOGFILE_PATH

            # Do not write to the log file if the log already exists.
            if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
            
                # Announce the gathering of geolocation data and pause for a second as to not rate-limit the API
                #Write-Host "Getting Latitude and Longitude from IP Address and writing to log" -ForegroundColor Yellow -BackgroundColor Black
                Start-Sleep -Seconds 1

                # Make web request to the geolocation API
                # For more info: https://ipgeolocation.io/documentation/ip-geolocation-api.html
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

                # Pull Data from the API response, and store them in variables
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                # Write all gathered data to the custom log file. It will look something like this:
                #
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }
            else {
                # Entry already exists in custom log file. Do nothing, optionally, remove the # from the line below for output
                # Write-Host "Event already exists in the custom log. Skipping." -ForegroundColor Gray -BackgroundColor Black
            }
        }
    }
}
``` 
 
</details>
 
## Description
- Configure and Deploy Azure Resources such as Log Analytics Workspace, Virtual Machines, and Azure Sentinel.
- Implement Network Rules for Network Security Group (NSG)
- Take A Look At Windows Security Event logs
- Use KQL Query Logs
- Enable gathering VM logs in Security Center
- Connect Log Analytics to VM
- Log into VM with Remote Desktop (fail 1 logon)
- Observe Event Viewer Logs in VM
- Turn off Windows Firewall on VM
- Download PowerShell Script
- Get Geolocation.io API Key
- Run Script To get Geo Data from attackers
- Create custom log in LAW to bring in our custom log
- Create custom fields/extract fields from raw custom log data
- Testing Extracts
- Setup map in sentinel with Latitude and Longitude (or country)
  
<details>
 
 <summary> 
  
 ## Configure VM and Deploy Resources
  
</summary
We will create a Virtual Machine that will be exposed to the internet where people around world will be able to attack it. Bad actors will try to login to this Virtual Machine once they've discovered that it's now online. While creating the Virtual Machine, we will create a new Resource Group as well.
 
We will create a Virtual Machine that will be exposed to the internet where people around world will be able to attack it. 
<p align="center"><img src="https://i.imgur.com/h3R75Bp.png" height="80%" width="80%" alt="Create Virtual Machine"/></p>
To make it susceptive to attacks, we will adjust the inbound rules as follows:
 <pre>
 <b>Source </b>
 any
 <b>Source port ranges </b> 
 * 
 <b>Destination </b>
 any 
 <b>Service </b>
 custom
 <b>Destination port ranges </b>
 *
 <b>Protocol</b>
 any
 <b>Priority</b>
 100</pre>

Bad actors will try to login to this Virtual Machine once they've discovered that it's now online. While creating the Virtual Machine, we will create a new Resource Group as well.
<p align="center"><img src="https://i.imgur.com/VENcOF8.png" height="80%" width="80%" alt="Create Virtual Machine"/></p>
 
 </details>  
 
 #
 
 <details>
 <summary>
  
## Create Our Log Ananlytics Workspace and Enable Defender
  
 </summary>  
Now, we are going to create our Log Analytics Workspace to receive or ingest logs from the virtual machine such as windows event logs and our custom logs that has geographic information in order to discover where the attackers are located. Our SIEM will be able to connect to the workspace to be able to display the geo-data on the map that will be created later in the lab. 
 
<p align="center"><img src="https://i.imgur.com/XOUSezh.png" height="90%" width="90%" alt="Create Log Analytics Workspace"/></p>
 
We will set up Microsoft Defender now to enable the ability to gather logs from the Virtual Machine.

We will toggle the Defender plan: Server to 'ON' and the Data Collection of Windows Security events to 'All Events'

<p align="center"><img src="https://i.imgur.com/yi6id7d.png" height="90%" width="90%" alt="Defender for Cloud"/></p>
<p align="center"><img src="https://i.imgur.com/udhv65g.png" height="90%" width="90%" alt="Defender for Cloud"/></p>
 
We can now go back to our log analytics workspace to connect our Virtual Machine. 

 </details> 
 
 # 
 
 <details>
 <summary>
 
## Disable Firewall and Run Powershell Code
 
 </summary> 
Now we will log into our Virtual Machine using Remote Desktop 
 
<p align="center"><img src="https://i.imgur.com/LxuSrwJ.png" height="80%" width="80%" alt="RDP"/></p>

By going to Event Viewer > Windows Logs > Security, we can see the security logs of our VM. Specifically, we can observe failed login attempts of the attackers.
 
<p align="center"><img src="https://i.imgur.com/Oerjh7t.png" height="90%" width="90%" alt="Event Viewer"/></p>

Now we will disable all Firewall settings on our VM (Domain Profile, Private Profile and Public Profile) to make it appear more vulnerable to attackers.

<p align="center"><img src="https://i.imgur.com/enyGgif.png" height="90%" width="90%" alt="Windows Firewall"/></p>

To get the geodata of the attackers, we will run the Powershell script I have pasted above. Before we do that, we have to retrieve our unique IP API key to insert into the code for it to run successfully. This can be done on https://ipgeolocation.io/

<p align="center"> <img src="https://i.imgur.com/fbKjYck.png" height="80%" width="80%" alt="IP Geo"/></p>

Your API key will replace where it says $API_KEY in the code (highlighted)
Now we will run the code on Powershell to retrieve the geodata of the attackers.

<p align="center"> <img src="https://i.imgur.com/j34oMvf.png" height="90%" width="90%" alt="Powershell"/></p>

</details> 

#

<details>
 
<summary> 

  
## Create a Custom Log and Utilize KQL
  
 </summary> 
The next thing that we'll do is create a custom log. We will go to the Log Analytics Workspace, create a custom log with the following file which can be retrieved from the virtual machine with the path >  C:\ProgramData\failed_rdp.log

<p align="center"> <img src="https://i.imgur.com/7fUFmvS.png" height="110%" width="110%" alt="custom log"/></p>
Since the custom log has been established, we can go to Logs and enter "FAILED_RDP_WITH_GEO_CL" in the Kusto Query Language (KQL) field and see logs of all the failed log in attempts.

<p align="center"> <img src="https://i.imgur.com/xAORM8K.png" height="100%" width="100%" alt="KQL"/></p>

 </details> 
 
 #
 <details> 
 <summary> 
  
## Create Workbook for World Map Visualization
  
 </summary> 
Now we will go to Microsoft Sentinel and create a new Workbook. 

We will run the following query that reflects the key points we require from our logs: latitude, longitude, sourcehost, label, destination, country.
<pre>
FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country
</pre>

We set the Visualization type to Map, creating a graphic of our attackers from all over the world.

<p align="center"> <img src="https://i.imgur.com/qOt4MpP.png" height="120%" width="120%" alt="Workbook"/></p>


 </details> 
 
 #
 <details> 
 <summary> 


## Attacks from around the world 24 hours later
 </summary> 
Here is the world map of incoming attacks after 24 hours from various countries.

<p align="center"> <img src="https://i.imgur.com/BL6O6OJ.png" height="150%" width="150%" alt="World Map"/></p>


`That's that end of the lab, be sure to delete the resource group that was created if you are done and it no longer has use.`

 </details> 


