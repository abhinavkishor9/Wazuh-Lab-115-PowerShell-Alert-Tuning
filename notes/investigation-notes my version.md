# Investigation Notes

## 1. Evidence Sources

The following sources were examined during the investigation:

- Wazuh alert records: `/var/ossec/logs/alerts/alerts.json`
- Original rule definition: `/var/ossec/ruleset/rules/0830-sysmon_id_11.xml`
- Local rule configuration: `/var/ossec/etc/rules/local_rules.xml`
- Wazuh rule testing utility: `/var/ossec/bin/wazuh-logtest`
- XML syntax validation: `xmllint`

## 2. Observed Alert Characteristics

| Field | Observed value |
|---|---|
| Rule ID | `92205` |
| Alert level | 9 |
| Event source | Sysmon |
| Event ID | 11 |
| Endpoint | `DESKTOP-9MMM37V` |
| Agent ID | `001` |
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Target directory | `C:\Windows\SystemTemp` |
| Filename pattern | `__PSScriptPolicyTest_*.ps1` |
| User | `NT AUTHORITY\SYSTEM` |
| Original MITRE mapping | T1105 |

The alert records showed the same general pattern occurring repeatedly, with changing temporary filenames and process IDs.

An example observed target filename was:

`C:\Windows\SystemTemp\__PSScriptPolicyTest_yqmbqao5.caf.ps1`

The records also showed a steadily increasing `firedtimes` value. This indicates repeated triggering as represented in the alert records, but it should not be interpreted as a verified count of unique malicious incidents.

## 3. Original Detection Logic

Rule `92205` was found in the installed Wazuh Sysmon Event ID 11 rules file.

Its relevant conditions were:

- The event must match parent rule `92203`.
- The target filename must match the configured Windows directory expression.
- The rule assigns alert level 9.
- The rule includes the MITRE ATT&CK technique T1105.

The configured directory expression includes patterns for Windows system, SysWOW64, and temp locations. The observed `SystemTemp` path matched the broader `Windows\system` portion of the expression.

This helps explain the alert behavior. It does not establish that the original rule is incorrect for all events matching its conditions.

## 4. Assessment

### Confirmed

- Rule `92205` generated repeated alerts for Sysmon Event ID 11.
- The observed process image was Windows PowerShell.
- The target filenames followed the `__PSScriptPolicyTest_*.ps1` pattern.
- The target directory was `C:\Windows\SystemTemp`.
- The user recorded in the events was `NT AUTHORITY\SYSTEM`.
- The original rule used a broader Windows directory-matching condition.
- The first custom-rule test attempt failed because Wazuh encountered an invalid nested rule structure.
- XML syntax validation later returned without an error.

### Plausible

The naming pattern and temporary directory are consistent with PowerShell script-policy testing. This is a plausible explanation for the repeated activity, but the observed filename alone cannot confirm the process that initiated the testing or establish that every event was benign.

### Unknown

- The exact initiating application or scheduled activity.
- Whether every observed file creation was benign.
- Whether the custom rule matches the intended events after the XML correction.
- Whether unrelated suspicious file-creation events remain detectable after tuning.
- Whether the custom configuration has been applied successfully to the running Wazuh manager.

## 5. Tuning Approach

A custom rule with ID `100502` was drafted in `local_rules.xml`.

The intended conditions were:

- The event must first match rule `92205`.
- The process image must match a PowerShell executable path.
- The target filename must match the observed `SystemTemp\__PSScriptPolicyTest_*.ps1` pattern.
- The custom rule is configured at level 0 to suppress the matching alert.

The intention is to scope the exception to the observed pattern rather than suppressing all PowerShell activity or all rule `92205` alerts.

A level-0 exception still carries risk: if malicious activity deliberately uses the same process and filename pattern, it could also be suppressed. Additional validation and monitoring are necessary.

## 6. Validation Results

The following validation results are supported by the available evidence:

1. A backup of `local_rules.xml` was created.
2. The initial custom-rule layout accidentally placed rule `100502` inside rule `100501`.
3. Wazuh reported `Invalid option 'rule' for rule '100501'` during the initial logtest attempt.
4. The XML structure was corrected so the rules were separate elements.
5. `xmllint --noout` subsequently returned without reporting an XML syntax error.
6. A representative JSON test event was submitted to `wazuh-logtest`.
7. The test event was decoded into fields including `win.eventdata.image`, `win.eventdata.targetFilename`, and `win.system.eventID`.
8. The available output does not confirm the final Phase 3 matched rule.



