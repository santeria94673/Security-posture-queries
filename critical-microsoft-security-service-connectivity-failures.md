# Critical Microsoft Security Service Connectivity Failures

## Overview

This query identifies devices that are unable to successfully connect to critical Microsoft security service endpoints over HTTPS. It explicitly separates failures related to Defender cloud protection from those related to Windows Update / Microsoft Update services.

The query helps highlight devices that may be affected by proxy, firewall, SSL inspection, or other network issues that can interfere with protection and update delivery.

## What the query checks

The query looks for:

- Network events with a populated `RemoteUrl`
- Connections to critical Microsoft security service domains
- HTTPS traffic (port 443)
- Failed connection attempts, including:
  - `ConnectionBlocked`
  - `ConnectionFailed`
  - `ConnectionTimeout`
  - `ConnectionReset`

It classifies each result into one of the following service categories:

- `Cloud Protection (Defender)`
- `Windows Update / Microsoft Update`

## How it works

1. Filters `DeviceNetworkEvents` for entries with a `RemoteUrl`.
2. Extracts the domain from the URL.
3. Matches the domain against:
   - Defender cloud protection endpoints
   - Windows Update / Microsoft Update endpoints
4. Assigns an explicit service label to each event.
5. Filters for HTTPS traffic on port 443.
6. Keeps only failed connection events based on `ActionType`.
7. Summarises the results by device, service, domain, and failure type.

## Use case

This query is useful for:

- Detecting devices that cannot reach Defender cloud protection services
- Identifying devices with Windows Update / Microsoft Update connectivity issues
- Troubleshooting firewall, proxy, or SSL inspection problems
- Supporting Defender health checks and update validation
- Enriching security posture and operational reporting

## Output

The output includes:

- Device name
- Device ID
- Service category
- Domain
- Action type
- Number of failures
- Last seen timestamp

## Query

```kql
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend Domain = case(
    RemoteUrl contains "//", tostring(parse_url(RemoteUrl).Host),
    RemoteUrl
)
| extend Service = case(
    Domain endswith ".wdcp.microsoft.com"
        or Domain endswith ".wdcpalt.microsoft.com"
        or Domain endswith ".wd.microsoft.com", "Cloud Protection (Defender)",
    Domain endswith ".update.microsoft.com"
        or Domain endswith ".delivery.mp.microsoft.com"
        or Domain endswith ".windowsupdate.com"
        or Domain == "ctldl.windowsupdate.com", "Windows Update / Microsoft Update",
    "Other"
)
| where Service != "Other"
| where RemotePort == 443
| where ActionType in ("ConnectionBlocked", "ConnectionFailed", "ConnectionTimeout", "ConnectionReset")
| summarize Failures = count(), LastSeen = max(Timestamp)
    by DeviceName, DeviceId, Service, Domain, ActionType
| order by Failures desc, LastSeen desc
