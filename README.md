# Failed RDP Logins Using Microsoft Azure Sentinel

## Introduction
The Powershell script in this repository is responsible for parsing out Windows Event Log information for failed RDP attacks and using a third party API to collect geographic information about the attackers location.

The script is used in this demo where I setup Azure Sentinel (SIEM) and connect it to a live virtual machine acting as a honey pot. We will observe RDP Brute Force attacks live from all around the world. Also, I will use a custom PowerShell script to look up the attackers Geolocation information and plot it on an Azure Sentinel Map!

## Prerequisites

To deploy Microsoft Sentinel Trainig Lab, **`you must have a Microsoft Azure subscription`**. If you do not have an existing Azure subscription, you can sign up for a free trial [here](https://azure.microsoft.com/free/).
The Powershell script in this repository that created by @joshmadakor1 is responsible for parsing out Windows Event Log information for failed RDP attacks and using a third party API [ipgeolocation.io](https://ipgeolocation.io/) to collect geographic information about the attackers location. You will `sign up` at ipgeolocation to get your `own` API key to load into the PowerShell script. 

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
  
 ## Configure and Deploy Resources
  
</summary
We will create a Virtual Machine that will be exposed to the internet where people around world will be able to attack it. Bad actors will try to login to this Virtual Machine once they've discovered that it's now online. While creating the Virtual Machine, we will create a new Resource Group as well.
 
We search `Virtual Machine` at top of the page in Azure, and once the page loads will choose the '`+ Create`' button to begin the first steps of creating the virtual machine.
<p align="center"><img src="https://i.imgur.com/CoIAYPA.png" height="70%" width="70%" alt="Create Virtual Machine"/></p>
 
Here we will choose to create a resource group (naming convention here is the name of the labname-rg). We're also selecting the '`East US`' as our preferred region due to resource cost and availability. After the region is selected, we will select the image of Windows 10 pro and the other settings will continue to be set at default. 
<p align="center"><img src="https://i.imgur.com/nZxgZCr.png" height="70%" width="70%" alt="Enter details for Virtual Machine"/></p>

<p align="center"><img src="https://i.imgur.com/35M9M7U.png" height="70%" width="70%" alt"Enter image user name and password"/></p>

Leave the default settings for the inbound port rules that are found below and be sure to check the box for "I confirm I have an eligible Windows 10/11 license with multi-tenant hosting rights."
 
   >**Note**: There will be a validation error message present if this check box is not selected while creating the virtual machine.
 
<p align="center"><img src="https://i.imgur.com/INNWJ1p.png" height="70%" width="70%" alt="Select license checkbox"/></p>
 
In the Networking portion, we will select to change the NIC Network Security Group (NSG) from Basic to Advanced to adjust the inbound rules of the NSG to allow everything into the Virtual Machine.
 
 <p align="center"><img src="https://i.imgur.com/CK6HXdb.png" height="70%" width="70%" alt="Settings for Networking of VM"/></p>
 
 Now, we'll need to remove (select 3 dots to the right of the page) the current default inbound rules on the virtual machine and will adjust them to rules that are most accepting of all traffic so that it can be found by the bad actors.
 <p align="center"><img src="https://i.imgur.com/8uLMfCn.png" heigh="70%" width="70%" alt="Remove Default Inound Rules"></p>
 
 We will select the `'Add an Inbound Rule'` link option and then make a change to the 'Destination port ranges' to an ' * ' as a wildcard to accept anything. Then, we'll select to change the Priority to 100 and make a name change to your liking (DANGER_ANY_IN). You can now select `'Add'` 
 <p align="center"><img src="https://i.imgur.com/i4dgfhu.png" height="70%" width="70%" alt="Create New NSG"/></p>
 Adjusting the inbound rules will appear as follows:
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
 
 The added inbound rule with the changes are now reflected here:
 <p align="center"><img src="https://i.imgur.com/XhQYX8n.png" height="100%" width="100%" alt="Updated NSG Inbound Rules"/></p>
 
We will now press 'OK' to move forward. 
Once these have been looked over, we can now select to `'Review + Create'`
<p align="center"><img src="https://i.imgur.com/9VP2ui7.png" height="70%" width="70%" alt="Review Create Virtual Machine"/></p>
 
Validation of Creation of VM --- This is the final step in creating the virtual Machine (VM) and see that it has been validated with a "Pass" and confirms all the details that have been added to the VM as a summary result. 
 <p align="center"><img src="https://i.imgur.com/6baoa2e.png" height="70%" width="70%" alt="Final State for Creating Virtual Machine"/></p>
 
 Select the Create Button
 <p align="center"><img src="https://i.imgur.com/Wb9Ggus.png" height="70%" width="70%" alt="Select Create Button for VM"/></p>
 
 This is the final confirmation displaying the creation of the Virtual Machine 
 <p align="center"><img src="https://i.imgur.com/fjDO3oV.png" height="70%" width="70%" alt="Deployment of VM"/></p>
 
 </details>  
 
 #
 
 <details>
 <summary>
  
## Create Our Log Ananlytics Workspace 
  
 </summary>  
Now, we are going to create our Log Analytics Workspace to receive or ingest logs from the virtual machine such as windows event logs and our custom logs that has geographic information in order to discover where the attackers are located. Our SIEM will be able to connect to the workspace to be able to display the geo-data on the map that will be created later in the lab. 
 
<p align="center"><img src="https://i.imgur.com/1ExWnBV.png" height="70%" width="70%" alt="Create Log Analytics Workspace"/></p>
 
<p align="center"><img src="https://i.imgur.com/Xq0jqhE.png" height="70%" width="70%" alt="Enter Details for Log Analytics Workspace"/></p>
 

 
Next, you will 'Review + Create' the log analytics workspace
<p align="center"><img src="https://i.imgur.com/zEMPI4D.png" height="70%" width="70%" alt="Review + Create LAW"/></p>

<p align="center"><img src="https://i.imgur.com/Gc4bGCG.png" height="70%" width="70%" alt="Create LaW"/></p>

<p align="center"><img src="https://i.imgur.com/YklC74u.png" height="70%" width="70%" alt="Deployment of LaW"/></p>
 
We can now search for 'Defender for Cloud' at the top of the page so that we can enable the ability to gather logs from the Virtual Machine.  
<p align="center"><img src="https://i.imgur.com/ZS8bpZv.png" height="70%" width="70%" alt="Defender for Cloud"/></p>
 
To do so, we will navigate to 'Environment Settings' then select the log analytics workspace that we created previously that is displayed as a selectable option. We will then, select to turn 'Azure Defender On' and then turn <b>OFF</b> 'SQL Servers on Machine'. Once this is done, you will select to '<b> Save </b>'. 
<p align="center"><img src="https://i.imgur.com/v7SNEGs.png" height="70%" width="70%" alt="Pricing & Settings"/></p>
 
Following this, we will select '`Data Collection`' in the left pane and enable '`All Events`' option under store additional raw data - windows securtity events then choose to '**`Save`**'.
<p align="center"><img src="https://i.imgur.com/lKdP5Ah.png" height="70%" width="70%" alt="Select All Events"/></p>
 
We can now go back to our log analytics workspace to connect our Virtual Machine. Search '`Log Analytics Workspace`' and then scroll down to select the Virtual Machine option. You will choose the VM that we created previously then select the chainlink to '`Connect`' the VM to the log analytics workspace. 
 
<p align="center"><img src="https://i.imgur.com/IdHGvQ4.png" height="70%" width="70%" alt="choose workspace"/></p>
<p align="center"><img src="https://i.imgur.com/9mSAa3S.png" height="70%" width="70%" alt="Select Virtual Machine in List"/></p>
 
 Select the Virtual Machine
<p align="center"><img src="https://i.imgur.com/r9xAInL.png" height="70%" width="70%" alt="select vm"/></p>
 
<p align="center"><img src="https://i.imgur.com/zSpANfP.png" height="70%" width="70%" alt="Connect Virtual Machine"/></p>

 </details> 
 
 # 
 
 <details>
 <summary>
 
## Setup Azure Sentinel
 
 </summary> 
We're going to set up Sentinel now that we can visualize the attack data that will display the details of the attackers location. You will do a quick search for `Sentinel` and then select the `Create` button at the top left or the middle of the screen. Then we will select the log analytics workspace (created earlier) that we want to connect to where all of our logs are. Once it's selected you can press the add button at the bottom of the screen.   
 
<p align="center"><img src="https://i.imgur.com/10d9qnu.png" height="70%" width="70%" alt="Sentinel"/></p>

Select **`Add`** here. 
 
<p align="center"><img src="https://i.imgur.com/FZvnWWI.png" height="70%" width="70%" alt="Add Workspace to Sentinel"/></p>

Now, we can go back to the virtual machine to check and see if it is finished connecting and if so, you will choose the VM to select the public IP address that we will be using to connect via Remote Desktop Connect (RDP)
<p align="center"><img src="https://i.imgur.com/zSGiuVw.png" height="70%" width="70%" alt="Public IP address"/></p>

<p align="center"><img src="https://i.imgur.com/jJw15fb.png" height="70%" width="70%" alt="RDP Login"/></p>

Once you successfully authenticate to the virtual machine and are logged in, search for Event Viewer and open the program.

As you can see there are several types of logs Windows Collects:
Application logs, Security Logs, Setup, System, and Forwarded Events.

<p align="center"> <img src="https://i.imgur.com/5AjVv7E.png" height="70%" width="70%" alt="Event Viewer Search"/></p>

<p align="center"> <img src="https://i.imgur.com/OnglJ9P.png" height="70%" width="70%" alt="Event Viewer"/></p>

Our focus in this lab will be on Windows Security events.

Click “`Security`” and observe the events.

As you can see there are several security events in event viewer. Let’s drill into one of these events.

Here, our focus will be event id **4625** for the failed logins. The details that available in the log that is selected are as follows: 
 
<li>Account name</li>
<li>Account domain</li>
<li>Failure reason</li>
<li>Logon process</li>
<li>Authentication package</li>
<li>Log name</li>
<li>Task</li>
<li>Category</li>
<li>Computer</li>
<li>Keywords</li>
<li>Workstation</li>
<li>Source Network Address (IP address)</li>
<li>And more</ul>
<p align="center"> <img src="https://i.imgur.com/KNq7Tmr.png" height="70%" width="70%" alt="Event Viewer 4625 log"/></p>

</details> 

#

<details>
 
<summary> 

## Gather API key for use with PowerShell
 
</summary>  

We will grab the IP address that is found here in Event Viewer that was from the failed login and use that address with <a href="https://ipgeolocation.io/">ipgeolocation.io</a> to get an accurate IP address lookup. This will allow us to plot ou the different attackers on a map. 
<p align="center"> <img src="https://i.imgur.com/Ophfhxt.png" height="70%" width="70%" alt="IP Geolocation"/></p>
There will be a need to disable the firewall on the VM so that it can respond to ICMP echo request so that the bad actors can discover it on the internet.
To do so, we can do a quick search in the virtual machine for 'wf.msc'.
<p align="center"><img src="https://i.imgur.com/GU9z44I.png" height="70%" width="70%" alt="wf msc. screentshot"/></p>
Select windows defender firewall properties
<p align="center"><img src="https://i.imgur.com/MwBKGvY.png" height="70%" width="70%" alt="windows defender firewall"/></p>

</details> 

#

<details> 
 
 <summary> 
  
## Remove Windows Firewall Restrictions

 </summary>
 
Now, select the domain profile tab > firewall state: <b>off</b>. Follow up by selecting the Private Profile > firewall state: <b>Off</b> and then Public Profile > firewall state: <b>Off</b>.
<p align="center"> <img src="https://i.imgur.com/8nwwdH8.png" height="70%" width="70%" alt="Disable Firewall"/></p>

After you've cycled through each of these, you can now select '`Apply`' then press '`OK`'.

We can go to the VM and open PowerShell ISE and this will be where our script will be loaded.
<p align="center"><img src="https://i.imgur.com/Vq5Tmxf.png" height="70%" width="70%" alt="powershell ise screenshot"/></p>

You can use the powershell script listed above or can be found <a href="https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1">here</a> by creating a new file inside PowerShell ISE and can name it Log_Exporter. For this script, you will need your own API Key that you can get by signing up for an account at <a href="https://ipgeolocation.io/signup.html">Sign Up</a>.

Without the API key, you will not be able to get the geo data that allows the location of the bad actors to be shown.
So go to your powershell click '`new script`' at the top left of the window and paste the script provided. Be sure to change the API key to your API key that you received when creating your account on ipgeolocation. 

<p align="center"> <img src="https://i.imgur.com/39362oA.png" height="70%" width="70%" alt="PowerShell File Creation"/></p>

 </details> 
 
 #
 <details> 
 <summary>
  
## Create a Custom Log
  
 </summary> 
The next thing that we'll do is create a custom log. We will go to the log analytics workspace and select '`Custom Log`' then choose to add the custom log. To get the log that has been created from the script, we can go to the virtual machine and the path of C:\ProgramData\ and select 'failed_rdp' file so C:\ProgramData\failed_rdp.log. 
<p align="center"> <img src="https://i.imgur.com/5DnQMZm.png" height="70%" width="70%" alt="failed_rdp file"/></p>

The first few lines that are present in the log file displays sample data that will be used. You will go to '`log analytics workspace`' and then select the workspace that we previously created.
<p align="center"><img src="https://i.imgur.com/KdTjnnL.png" height="70%" width="70%" alt="select workspace"/></p>

After choosing the workspace, you will select `'Custom Log'` on the left pane. 

<p align="center"><img src="https://i.imgur.com/jNp2UCm.png" height="25%" width="25%" alt="select custom log"/></p>

Upon the custom log page, you can select the '`+ Add custom log`' button at the top left or the '`Add custom log`' button in the center of the page (there is no preference).
<p align="center"><img src="https://i.imgur.com/maWRcws.png" height="70%" width="70%" alt="add custom log"/></p>

To get the log file, we will go to our virtual machine and copy the logs that are found in failed_rdp and paste them into notepad on our local computer. You can save it to your desktop so that it can be found easily and this can be named failed_rdp.log as well (for ease of search on the local computer).
<p align="center"><img src="https://i.imgur.com/JEZQeYw.png" height="70%" width="70%" alt="add customer log file"/></p>

This is what we will see that gives you an idea of the sampe logs that we will use later to create a query.
<p align="center"><img src="https://i.imgur.com/Tw1cTik.png" height="70%" width="70%" alt="record delimiter"/></p>

The collection path is where the logs will actually live on the VM and remember that the path was "C:\ProgramData\failed_rdp.log" that we will add here. Be sure that the path is correct or the logs will not be collected correctly. 
<p align="center"><img src="https://i.imgur.com/DqVb7o9.png" height="70%" width="70%" alt="collection path"/></p>

Here we'll create your custom name and a description of what the log will do. An example here could be "Log will gather details about the location and users that failed to login into RDP".
<p align="center"><img src="https://i.imgur.com/AzEEZS9.png" height="70%" width="70%" alt="details for log"/></p>

Review + Create will be the final steps here for the custom log and it gives you an overview of what you've just created in case you want to go back and make adjustments or necessary changes. 
<p align="center"><img src="https://i.imgur.com/hOtyCXB.png" height="70%" width="70%" alt="review + create custom log"/></p>

 </details> 
 
 #
 <details> 
 <summary> 
  
## Utilize KQL Kusto Query
  
 </summary> 
 
Since the custom log has been established, we can go to '`Logs`' on the left pane and we will enter "`FAILED_RDP_WITH_GEO_CL`" in the Kusto Query Language (KQL) field.

A Kusto query is a read-only request to process data and return results. The request is stated in plain text, using a data-flow model that is easy to read, author, and automate. Kusto queries are made of one or more query statements. (learn more [here](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)) 

Here is an example for <b> SecurityEvent</b> of failed log in attempts <b> where</b> the EventID *#4625#* </b>:
```elm
SecurityEvent
| where EventID == 4625
```
 
In the raw data column of the logs, it contains the entire line of each of the custom logs that we created for "FAILED_RDP_WITH_GEO_CL. With the raw data, we will extract certain fields from it so that we can create columns that will be displayed as a result.
<p align="center"><img src="https://i.imgur.com/gqcL9Vv.png" height="70%" width="70%" alt="failed rdp with geo raw column"/></p>


To extract the data, you will select one of the results and expanding it using the caret and then right-click on the raw data. After right-clicking, you select the option of "`extract fields from 'FAILED_RDP_WITH_GEO'.`"
<p align="center"><img src="https://i.imgur.com/MHTUEa1.png" height="70%" width="70%" alt="extract data"/></p>

We will be extracting each of these fields that are found in the raw data. The first field that we will be extracting will be the '`latitude`' field. So we will hightlight the numbers that follow the colon after latitude. Enter the field title name manually and select numeric as the field type. 
<p align="center"><img src="https://i.imgur.com/nVIINal.png" height="70%" width="70%" alt="extract latitude"/></p>

We will continue to do this for each of the fields present in raw data:
<pre>
latitude
longitude
destination host
username 
sourcehost
state
country
timestamp</pre>
After selecting to extract the data for latitude the results will yield the following for the search results and matches. Once you've verified that the search results align with the correct outcome for latitude, you will press the '`Save Extration`' button at the bottom of the page. 
<p align="center"><img src="https://i.imgur.com/vCwgDDs.png" height="70%" width="70%" alt="extract latitude"/></p>

If for some reason, the longitude or another field does not properly hightlight in the search result, click the pencil in the right hand corner then select '`modify this highlight`'. 
<p align="center"><img src="https://i.imgur.com/0cL4EKS.png" height="70%" width="70%" alt="modify hightlight"/></p>

Here we are getting the data for the destinationhost that follow the same steps as before. The destination host will be the virtual machine that we created earlier. 
<p align="center"><img src="https://i.imgur.com/yHWpm2Y.png" height="70%" width="70%" alt="extract destination host"/></p>

The next item that we will extract will be the username for the user that will used to log into the virtual machine. We will see the different user names that are tried in an attempt to log into the virtual machine. 

<p align="center"><img src="https://i.imgur.com/edvt45U.png" height="70%" width="70%" alt="extract username"/></p>
<p align="center"><img src="https://i.imgur.com/FmIHa1s.png" height="70%" width="70%" alt="extrace username search results"/></p>

Sourcehost will be the IP address that was used for the attempted login
<p align="center"><img src="https://i.imgur.com/pQGat9z.png" height="70%" width="70%" alt="extract source host"/></p>
<p align="center"><img src="https://i.imgur.com/CTMfRfI.png" height="70%" width="70%" alt="extract source host search results"/></p>

Next will be the extraction for State/Province
<p align="center"><img src="https://i.imgur.com/MwiL48B.png" height="70%" width="70%" alt="extract state or province"/></p>
<p align="center"><img src="https://i.imgur.com/CCOBbCw.png" height="70%" width="70%" alt="extract state or province search results"/></p>

<p align="center"><img src="https://i.imgur.com/9cP55he.png" height="70%" width="70%" alt="extract country"/></p>
<p align="center"><img src="https://i.imgur.com/yHpWRn6.png" height="70%" width="70%" alt="extract country search results"/></p>

<p align="center"><img src="https://i.imgur.com/o3y1bp6.png" height="70%" width="70%" alt="exact label"/></p>
<p align="center"><img src="https://i.imgur.com/SoMKdTV.png" height="70%" width="70%" alt="extract label search results"/></p>

<p align="center"><img src="https://i.imgur.com/yFQvXS0.png" height="70%" width="70%" alt="exact timestamp"/></p>
<p align="center"><img src="https://i.imgur.com/QdO2DJ8.png" height="70%" width="70%" alt="extract timestamp search results"/></p>

If we are to go back to sentinel, we can see an overview of the events that have happened to the virtual machine and can be found below:
<p align="center"><img src="https://i.imgur.com/Hu98jqG.png" height="70%" width="70%" alt="exact timestamp"/></p>

Now we will set up our geo map in our workbook. 
<p align="center"><img src="https://i.imgur.com/C2LTEA9.png" height="70%" width="70%" alt="sentinel workbooks select"/></p>

Select the `+ Add workbook` button new the top of the page

<p align="center"><img src="https://i.imgur.com/xNVaojA.png" height="70%" width="70%" alt="add workbook"/></p>

After the workbook loads, you will select the `Edit` button and remove each of the widgets that are pre-loaded queries as we will be adding our own. 

<p align="center"><img src="https://i.imgur.com/3ZAPODj.png" height="70%" width="70%" alt="add workbook"/></p>

Select the '`+Add`' button and then select to '`Add Query`'. 

<p align="center"><img src="https://i.imgur.com/GvTpvUH.png" height="70%" width="70%" alt="add query"/></p>

We will add the following query that reflects what we have created from the raw data of the logs:

```kql
FAILED_RDP_WITH_GEO_CL | summarize event_count=count() by sourcehost_CF, latitude_CF, longitude_CF, country_CF, label_CF, destinationhost_CF
| where destinationhost_CF != "samplehost"
| where sourcehost_CF != ""
```

## Create Workbook to Provide Map Visualization
<p align="center"><img src="https://i.imgur.com/eyXFcVn.png" height="70%" width="70%" alt="change visualization to map"/>
</p>

You will apply the following to the Map Settings:
<pre>
<h2>Layout Settings</h2>
<b>Location Info using</b>
Latitude/Longitude
<b>Latitude</b>
latitude_CF
<b>Longitude</b>
longitude_CF
<b>Size by</b>
event_count
<b>Aggregation for location</b>
Sum of Value
<b>Minimum region size</b>
20
<b>Maximum region size</b>
70
<b>Default region size</b>
10
<b>Minimum value</b>
(auto)
<b>Maximum value</b>
(auto)
<b>Opacity of items on Map</b>
0.7
<h2>Color Settings</h2>

<b>Coloring Type</b>
Heatmap
<b>Color by</b>
latitude_CF
<b>Aggregation for color</b>
Sum of value
<b>Color palette</b>
Green to Red
<b>Minimum value</b>
(auto)
<b>Maximum value</b>
(auto)
<h2>Metric Settings</h2>
<b>Matric Label</b>
label_CF
<b>Matric Value</b>
event_count
<b>Create 'Others' group after</b>
10
</pre>
Then we will save the map settings that we have put in place
<p align="center">
<img src="https://i.imgur.com/y4i26f3.png" height="70%" width="70%" alt="save map settings"/>
</p>

Finally, this is our last image of more countries deciding to join in on the fun of attempting to access our virtual machine in about a span of 18 hours. 
<p align="center">
<img src="https://i.imgur.com/Ia7U0yS.png" height="70%" width="70%" alt="last image for map attack"/>
</p>

`That's that end of the lab, be sure to delete the resource group that was created if you are done and it no longer has use.`

