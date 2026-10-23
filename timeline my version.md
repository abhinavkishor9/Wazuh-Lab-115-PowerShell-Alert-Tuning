# Investigation Timeline

## 1. Initial Alert Review

**Date:** 2026-10-22 to 2026-10-23

- Repeated Wazuh alerts were observed for rule `92205`.
- The alerts were configured at level 9.
- The event source was Sysmon Event ID 11.
- The observed PowerShell process created files under `C:\Windows\SystemTemp`.
- The filenames followed the `__PSScriptPolicyTest_*.ps1` pattern.
- The recorded user was `NT AUTHORITY\SYSTEM`.

**Result:** A recurring file-creation pattern was identified for further investigation.

## 2. Original Rule Examination

- Searched the Wazuh rules directories for rule `92205`.
- Located the rule in `0830-sysmon_id_11.xml`.
- Examined the parent rule relationship and target filename condition.
- Identified the broad Windows directory matching that included the observed `SystemTemp` path.

**Result:** The original detection logic provided a plausible explanation for the alerts.

## 3. Custom Rule Planning

- Decided to preserve the vendor rule.
- Checked existing local rule IDs.
- Found existing rules `100001` and `100501`.
- Selected `100502` for the proposed local tuning rule.
- Created a backup of `local_rules.xml`.

**Result:** A local configuration change was prepared without directly modifying the vendor ruleset.

## 4. First Rule-Testing Attempt

- Added the proposed `100502` rule.
- Ran `xmllint` to check XML syntax.
- Started `wazuh-logtest`.
- Wazuh returned `Invalid option 'rule' for rule '100501'`.

**Result:** Rule testing could not initialize because the custom rule was nested inside another rule.

## 5. XML Structure Investigation

- Displayed the configuration with line numbers.
- Identified the misplaced opening and closing rule tags.
- Determined that rules `100501` and `100502` needed to be separate sibling elements.

**Result:** The cause of the rule initialization error was identified.

## 6. XML Structure Correction

- Reorganized `local_rules.xml` so the rules were separate elements inside the existing group.
- Re-ran `xmllint --noout`.
- XML validation returned without reporting an error.

**Result:** The corrected file passed the XML syntax check.

## 7. Representative Event Testing

- Started `wazuh-logtest` again.
- Submitted a representative Sysmon Event ID 11 JSON fixture.
- Observed Phase 1 pre-decoding and Phase 2 JSON decoding.
- Confirmed that the expected image, target filename, user, and event ID fields were decoded.

**Result:** Field decoding was demonstrated. The available output did not establish a successful Phase 3 match for rule `100502`.

