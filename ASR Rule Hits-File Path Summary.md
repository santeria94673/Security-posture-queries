# ASR Rule Activity - File Path Summary

## Overview

This query returns unique Attack Surface Reduction (ASR) rule events observed in the last 30 days. It shows the device name, ASR rule action, and full file path involved in the event.

The query is useful for identifying where ASR rules are firing, which files are being affected, and spotting recurring patterns across devices. LSASS credential theft events are excluded from this view.

## What the query checks

The query looks for:

- Device events from the last 30 days
- Actions where the `ActionType` starts with `Asr`
- Excludes `AsrLsassCredentialTheft` events
- Builds a full file path from folder path and file name
- Returns distinct combinations of:
  - Device name
  - ASR rule
  - File path

## How it works

1. Filters `DeviceEvents` to the last 30 days.
2. Keeps only events where the action type starts with `Asr`.
3. Excludes LSASS credential theft related ASR events.
4. Combines folder path and file name into a single full path value.
5. Normalises `DeviceName` as a string.
6. Uses the action type as the ASR rule identifier.
7. Returns only distinct results to reduce duplicate noise.

## Use case

This query is useful for:

- Reviewing ASR rule activity across endpoints
- Investigating which files commonly trigger ASR events
- Supporting ASR tuning and exclusion review
- Identifying recurring blocked or audited activity
- Building reporting views for ASR rule visibility

## Output

The output includes:

- Device name
- ASR rule
- Full file path

## Query

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Asr"
| where ActionType !startswith "AsrLsassCredentialTheft"
| extend FullPath = strcat(FolderPath, "\\", FileName)
| extend DeviceName = tostring(DeviceName)
| extend ASRRule = ActionType
| project DeviceName, ASRRule, FullPath
| distinct DeviceName, ASRRule, FullPath
