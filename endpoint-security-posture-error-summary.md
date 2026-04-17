# Endpoint Security Posture - Error Summary

## Overview

This query identifies devices with non-compliant Microsoft Defender security configurations across key protection controls. It focuses only on devices with errors, making it easier to prioritise remediation instead of reviewing fully compliant systems.

## What the query checks

The query reviews the latest available status for the following Microsoft Defender secure configuration controls:

* Sensor enabled
* Sensor data collection
* Impaired communications
* Tamper protection
* Antivirus enabled
* Antivirus signature version
* Realtime protection
* Behaviour monitoring
* PUA protection
* Antivirus reporting
* Cloud protection
* Network protection

## How it works

1. Filters `DeviceTvmSecureConfigurationAssessment` for selected secure configuration IDs.
2. Gets the latest assessment result per device and configuration.
3. Maps each configuration ID to a readable control name.
4. Labels results as:

   * `OK` for compliant
   * `ERROR` for non-compliant
   * `N/A` for not applicable
5. Counts the number of errors per device.
6. Returns only devices with one or more errors.
7. Joins the results with `DeviceInfo` to include operating system, join type, machine group, and last seen timestamp.

## Use case

This query is useful for:

* Secure configuration health checks
* Defender hardening reviews
* Monthly security reporting
* Identifying devices that require remediation
* Quickly highlighting protection gaps without compliant noise

## Output

The output includes:

* Device name
* Machine group
* OS platform
* Join type
* Last seen timestamp
* Total error count
* Individual status for each checked control

## Query

```kql
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-91", "scid-2000", "scid-2001", "scid-2002", "scid-2003",
                            "scid-2010", "scid-2011", "scid-2012", "scid-2013",
                            "scid-2014", "scid-2016", "scid-96")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceName, ConfigurationId
| extend Test = case(
        ConfigurationId == "scid-2000", "SensorEnabled",
        ConfigurationId == "scid-2001", "SensorDataCollection",
        ConfigurationId == "scid-2002", "ImpairedCommunications",
        ConfigurationId == "scid-2003", "TamperProtection",
        ConfigurationId == "scid-2010", "AntivirusEnabled",
        ConfigurationId == "scid-2011", "AntivirusSignatureVersion",
        ConfigurationId == "scid-2012", "RealtimeProtection",
        ConfigurationId == "scid-91", "BehaviorMonitoring",
        ConfigurationId == "scid-2013", "PUAProtection",
        ConfigurationId == "scid-2014", "AntivirusReporting",
        ConfigurationId == "scid-2016", "CloudProtection",
        ConfigurationId == "scid-96", "NetworkProtection",
        "N/A")
| extend Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "OK", "ERROR")
| summarize Tests = make_bag(pack(Test, Result)), ErrorCount = countif(Result == "ERROR") by DeviceName
| where ErrorCount > 0
| evaluate bag_unpack(Tests)
| join kind=inner (
    DeviceInfo
    | where Timestamp >= ago(7d)
    | summarize arg_max(Timestamp, OSPlatform, JoinType, MachineGroup) by DeviceName
    | extend OSPlatform = iff(isempty(OSPlatform), "Unknown", OSPlatform),
              JoinType = iff(isempty(JoinType), "Unknown", JoinType),
              MachineGroup = iff(isempty(MachineGroup), "Unknown", MachineGroup),
              LastSeen = Timestamp
    | project DeviceName, MachineGroup, OSPlatform, JoinType, LastSeen
) on DeviceName
| project DeviceName, MachineGroup, OSPlatform, JoinType, LastSeen, ErrorCount,
          SensorEnabled, SensorDataCollection, ImpairedCommunications, TamperProtection,
          AntivirusEnabled, AntivirusSignatureVersion, RealtimeProtection, BehaviorMonitoring,
          PUAProtection, AntivirusReporting, CloudProtection, NetworkProtection
| order by ErrorCount desc, LastSeen desc
```

## Notes

* The query uses the latest available assessment per device and control.
* Devices without errors are intentionally excluded.
* `N/A` indicates controls that are not applicable on that device.
* You can expand or reduce the checked controls by adjusting the `ConfigurationId` list and mapping section.

