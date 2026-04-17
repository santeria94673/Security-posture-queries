# ASR Configuration State - Device Overview

## Overview

This query provides visibility into the current Attack Surface Reduction (ASR) configuration across devices. It extracts ASR configuration states from Defender telemetry and expands them into readable columns per device.

The results are enriched with device context such as machine group and join type to support filtering, segmentation, and reporting.

## What the query checks

The query retrieves:

- ASR configuration states from `DeviceTvmInfoGathering`
- Device context from `DeviceInfo`
- Latest machine group and join type per device
- Expanded ASR rule configuration per device

## How it works

1. Reads data from `DeviceTvmInfoGathering`.
2. Parses the `AdditionalFields.AsrConfigurationStates` JSON field.
3. Joins with `DeviceInfo` to enrich results with:
   - Machine group
   - Join type
4. Normalises empty values to `Unknown`.
5. Projects key device fields and ASR configuration data.
6. Expands the ASR configuration JSON into individual columns using `bag_unpack`.

## Use case

This query is useful for:

- Reviewing ASR configuration across all devices
- Validating ASR policy deployment
- Identifying inconsistent configurations between device groups
- Supporting ASR rollout and tuning
- Building reporting views for security posture

## Output

The output includes:

- Device name
- Last seen time
- OS platform
- Machine group
- Join type
- Individual ASR rule configuration states (expanded as columns)

## Query

```kql
DeviceTvmInfoGathering
| extend ASR = parse_json(AdditionalFields.AsrConfigurationStates)
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, MachineGroup, JoinType) by DeviceName
    | extend MachineGroup = iff(isempty(MachineGroup), "Unknown", MachineGroup),
             JoinType     = iff(isempty(JoinType), "Unknown", JoinType)
    | project DeviceName,
              DI_MachineGroup = MachineGroup,
              DI_JoinType     = JoinType
) on DeviceName
| project
    DeviceName,
    LastSeenTime,
    OSPlatform,
    MachineGroup = DI_MachineGroup,
    JoinType     = DI_JoinType,
    ASR
| evaluate bag_unpack(ASR)
