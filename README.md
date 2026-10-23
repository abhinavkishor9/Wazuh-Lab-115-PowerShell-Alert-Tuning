# Wazuh Lab 115 — PowerShell Alert Tuning

## Overview

This lab investigates repetitive Wazuh alerts generated when PowerShell creates temporary script files under the Windows `SystemTemp` directory. The objective is to understand the original detection rule, examine the associated Sysmon evidence, and develop a narrowly scoped custom rule to reduce repetitive alerts without suppressing unrelated file-creation activity.

The investigation focuses on Wazuh rule `92205`, Sysmon Event ID 11, and custom rule development in `local_rules.xml`.

## Lab Objectives

- Investigate repeated PowerShell file-creation alerts in Wazuh.
- Examine the original detection logic behind rule `92205`.
- Correlate alert metadata with Sysmon file-creation events.
- Identify the recurring filename and directory pattern.
- Develop a custom rule targeting the observed activity.
- Validate XML syntax and troubleshoot rule-loading errors.
- Test rule matching before applying configuration changes.
- Document evidence, limitations, and tuning considerations.

## Environment

| Component | Details |
|---|---|
| SIEM / HIDS | Wazuh |
| Wazuh version reported by logtest | 4.13.1 |
| Endpoint | `DESKTOP-9MMM37V` |
| Agent ID | `001` |
| Endpoint operating system | Windows 11 |
| Telemetry source | Sysmon |
| Event ID | 11 — File creation |
| Original rule | `92205` |
| Original alert level | 9 |
| Custom rule under development | `100502` |
| Custom rules file | `/var/ossec/etc/rules/local_rules.xml` |

## Scenario

Wazuh repeatedly generated level-9 alerts describing PowerShell file creation in a Windows system directory. Examination of the alert records showed PowerShell creating files matching the `__PSScriptPolicyTest_*.ps1` naming pattern under `C:\Windows\SystemTemp`.

The events included the PowerShell executable path, target filename, and `NT AUTHORITY\SYSTEM` as the user. The repeated pattern suggested possible benign script-policy testing, but the available evidence did not independently establish the activity's origin or conclusively prove it was benign.

The investigation therefore focused on understanding the existing detection rule and designing a narrowly scoped exception rather than disabling the detection altogether.

## Detection Rule Analysis

The original rule was located in:

`/var/ossec/ruleset/rules/0830-sysmon_id_11.xml`

Its relevant configuration was:

```xml
<rule id="92205" level="9">
  <if_sid>92203</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)Windows\\\\(system|syswow64|temp)</field>
  <options>no_full_log</options>
  <description>Powershell process created an executable file in Windows root folder</description>
  <mitre>
    <id>T1105</id>
  </mitre>
</rule>
```

The rule matches a parent rule and a target filename containing one of the specified Windows directory patterns. The broad directory matching helps explain why the observed `SystemTemp` paths triggered the rule.

The MITRE ATT&CK mapping is part of the original rule configuration. It does not, by itself, establish that ingress tool transfer occurred during these events.

## Investigation Workflow

1. Locate rule `92205` in the installed Wazuh ruleset.
2. Examine the corresponding alert records in `alerts.json`.
3. Identify recurring process, user, directory, and filename characteristics.
4. Back up `local_rules.xml` before modifying it.
5. Develop a custom rule using ID `100502`.
6. Validate the XML configuration with `xmllint`.
7. Run `wazuh-logtest` to investigate rule matching.
8. Correct the nested XML rule structure discovered during troubleshooting.
9. Revalidate the configuration and continue testing before applying the change.

## Key Findings

- Rule `92205` generated repeated level-9 alerts for Sysmon Event ID 11.
- The observed process was Windows PowerShell.
- The recurring target path was `C:\Windows\SystemTemp`.
- The observed filenames followed the `__PSScriptPolicyTest_*.ps1` pattern.
- The events identified `NT AUTHORITY\SYSTEM` as the user.
- The original rule's directory-matching condition was broader than the specific filename pattern observed.
- An incorrectly nested custom rule caused `wazuh-logtest` to fail during initialization.
- XML validation subsequently completed without reporting syntax errors.
- Successful custom-rule matching and operational deployment remain unconfirmed.

## Troubleshooting Lessons

### Nested rule structure

Wazuh rules must be separate sibling elements within their enclosing group. A `<rule>` element cannot contain another `<rule>` element.

### XML validation versus rule validation

A successful `xmllint` run establishes XML syntax validity. It does not establish that Wazuh accepts every rule option or that a rule matches the intended event.

### Rule-matching verification

A custom rule must be tested against representative telemetry. The decoded fields, parent-rule relationship, and final matched rule should be inspected before applying a tuning change.

### Narrowly scoped tuning

Suppressing every alert from PowerShell or disabling rule `92205` globally could hide legitimate suspicious activity. Any exception should be restricted to a well-understood pattern and supported by additional validation.

## Current Status

**Status: Investigation and validation in progress.**

The original rule and alert pattern were examined, a custom rule was drafted, and an XML structure problem was identified and corrected. XML syntax validation passed afterward.

The available evidence does not yet demonstrate that the custom rule successfully matched at level 0 in Phase 3. The Wazuh manager has not been confirmed as restarted with the validated configuration, and the effectiveness of the tuning remains unverified.

## Lessons Learned

- Repeated high-severity alerts warrant investigation rather than automatic suppression.
- Filename patterns provide useful context but are not proof of benign activity.
- Vendor rules should be preserved; custom tuning belongs in the local rules configuration.
- Backups, syntax checks, rule tests, and post-deployment verification are separate steps.
- A successful configuration edit is not the same as a successfully deployed detection change.

## Safety and Scope

This lab uses a controlled Windows endpoint and a Wazuh manager. The investigation focuses on detection quality, evidence-based analysis, configuration validation, and reducing repetitive alerts without broadly disabling security monitoring.
