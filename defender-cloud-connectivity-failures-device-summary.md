# Defender Cloud Connectivity Failures - Device Summary

## Overview

This query identifies devices that are unable to successfully connect to Microsoft Defender cloud endpoints. These endpoints are required for cloud-delivered protection, reputation services, and other Defender features.

The query focuses on failed HTTPS connections to key Defender domains and returns a distinct list of affected devices.

## What the query checks

The query looks for:

- Network events with a populated `RemoteUrl`
- Connections to Defender-related domains:
  - `.wdcp.microsoft.com`
  - `.wdcpalt.microsoft.com`
  - `.wd.microsoft.com`
- HTTPS traffic (port 443)
- Failed connection attempts, including:
  - Blocked
  - Failed
  - Timeout
  - Reset

## How it works

1. Filters `DeviceNetworkEvents` for entries with a `RemoteUrl`.
2. Extracts the domain from the URL.
3. Matches domains against known Defender cloud endpoints.
4. Filters for HTTPS traffic (port 443).
5. Keeps only failed connection events based on `ActionType`.
6. Projects relevant fields for investigation.
7. Returns a distinct list of affected devices to reduce noise.

## Use case

This query is useful for:

- Detecting devices that cannot reach Defender cloud services
- Identifying proxy, firewall, or SSL inspection issues
- Troubleshooting cloud-delivered protection (MAPS)
- Supporting security posture and health checks
- Validating network requirements for Defender

## Output

The output includes:

- Device ID
- Device name

## Query

```kql
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend Domain = case(
    RemoteUrl contains "//", parse_url(RemoteUrl).Host,
    RemoteUrl
)
| where Domain endswith ".wdcp.microsoft.com"
    or Domain endswith ".wdcpalt.microsoft.com"
    or Domain endswith ".wd.microsoft.com"
| where RemotePort == 443
| where ActionType in ("ConnectionBlocked", "ConnectionFailed", "ConnectionTimeout", "ConnectionReset")
| project Timestamp, DeviceId, DeviceName, Domain, RemotePort, ActionType, RemoteUrl, InitiatingProcessFileName
| distinct DeviceId, DeviceName
