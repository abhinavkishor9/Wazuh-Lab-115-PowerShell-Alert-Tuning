# Lab 115 — Troubleshooting Notes

## 1. Purpose

This document records the problems encountered while developing a custom Wazuh rule to tune repetitive PowerShell file-creation alerts.

The troubleshooting process focused on the existing rule definition, XML structure, syntax validation, and Wazuh rule testing.

## 2. Issue: Repetitive Rule 92205 Alerts

### Symptoms

Wazuh repeatedly generated level-9 alerts with the description:

`Powershell process created an executable file in Windows root folder`

The corresponding events showed Sysmon Event ID 11 and PowerShell creating temporary script files under:

`C:\Windows\SystemTemp`

The filenames followed the pattern:

`__PSScriptPolicyTest_*.ps1`

### Investigation

The original rule was located using:

```bash
sudo grep -R -n -B 10 -A 25 '92205' \
  /var/ossec/etc/rules /var/ossec/ruleset/rules 2>/dev/null
```

The rule was found in:

`/var/ossec/ruleset/rules/0830-sysmon_id_11.xml`

Its target filename condition covered multiple Windows directory patterns. The observed `SystemTemp` path matched the broad directory expression.

### Lesson

Inspect the original rule and the underlying event before tuning an alert. Repetition and a familiar filename do not independently prove benign activity.

## 3. Issue: Invalid Nested Rule

### Error

The first `wazuh-logtest` attempt returned:

```text
ERROR: Invalid option 'rule' for rule '100501'.
ERROR: (7311): Failure to initializing session
```

### Cause

Inspection of the numbered XML file showed that custom rule `100502` had been inserted inside rule `100501`, before rule `100501` had been closed.

The problematic structure was effectively:

```xml
<rule id="100501" level="5">
  <if_sid>61606</if_sid>
  <description>Lab 107: Sysmon service state changed (Event ID 4).</description>

  <rule id="100502" level="0">
    <if_sid>92205</if_sid>
  </rule>

  <group>sysmon_service_state_change,</group>
</rule>
```

A Wazuh rule must not contain another rule as a nested child. Both custom rules must be sibling elements inside the enclosing group.

### Correction

The XML was reorganized so that rules `100001`, `100501`, and `100502` were separate elements inside the existing `<group>`.

The final structure should follow this pattern:

```xml
<group name="local,syslog,sshd,">

  <rule id="100001" level="5">
    <!-- Existing rule conditions -->
  </rule>

  <rule id="100501" level="5">
    <!-- Existing rule conditions -->
  </rule>

  <rule id="100502" level="0">
    <!-- New tuning conditions -->
  </rule>

</group>
```

This is a structural illustration; the existing rules must retain their actual conditions.

### Lesson

Use line-numbered output to identify the exact placement of XML elements:

```bash
sudo nl -ba /var/ossec/etc/rules/local_rules.xml
```

## 4. XML Syntax Validation

After correcting the structure, XML validation was run:

```bash
sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml
```

The command returned without output, indicating that the file passed this XML syntax check.

However, XML validity does not prove that Wazuh accepts every rule option or that the intended event will match the custom rule.

## 5. Rule-Matching Validation

The rule testing utility was launched with:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

A representative JSON event was submitted:

```json
{"win":{"system":{"eventID":"11"},"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","targetFilename":"C:\\Windows\\SystemTemp\\__PSScriptPolicyTest_test123.ps1","user":"NT AUTHORITY\\SYSTEM"}}}
```

The available output showed that Wazuh decoded fields including:

- `win.eventdata.image`
- `win.eventdata.targetFilename`
- `win.eventdata.user`
- `win.system.eventID`

The output available for this investigation did not confirm the final Phase 3 rule match.

### Next action

Re-run the test and inspect Phase 3. Confirm whether the final matched rule is `100502` at level 0 before proceeding.

If the event does not match, review the decoded field values, the regular expressions, and the parent rule relationship. Do not assume a successful match from the XML syntax check alone.

## 6. Backup and Recovery

Before editing, a backup was created:

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml.bak-lab115
```

The backup can be inspected with:

```bash
sudo ls -l /var/ossec/etc/rules/local_rules.xml*
```

If a future change breaks the configuration, preserve the current file and review the backup before restoring anything. Do not overwrite the active file blindly, because it may contain later changes.

## 7. Deployment Safety

Do not restart the Wazuh manager solely because XML validation passed.

Before deployment:

1. Confirm the intended event matches rule `100502`.
2. Confirm a control event still triggers the original detection when appropriate.
3. Run the supported Wazuh configuration validation procedure.
4. Review the configuration and backup.
5. Restart the manager only after validation succeeds.
6. Verify service health and alert behavior after the restart.

The exact behavior of level-0 child rules should be confirmed through testing rather than assumed.

## 8. Key Lessons

- Rule nesting errors can prevent `wazuh-logtest` from initializing.
- XML validation and Wazuh rule matching validate different things.
- A decoded event is not proof that a custom rule matched.
- Custom exceptions should target a specific, investigated pattern.
- A level-0 rule can suppress matching activity, including activity that may be malicious.
- Preserve the original vendor rules and use local custom rules for tuning.
- Record unverified outcomes as pending rather than claiming success.
