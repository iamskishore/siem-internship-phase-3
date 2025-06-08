# Credential Dumping and Exfiltration - Mimikatz

## Scenario Description

  Credential dumping is a common post-exploitation technique where attackers extract credentials from memory to escalate privileges or move laterally across a network. Mimikatz is a widely used tool by attackers to dump credentials from the Local Security Authority Subsystem Service (LSASS) on Windows systems. After dumping, attackers often exfiltrate stolen credentials or hashes, commonly over HTTPS to evade detection.
## Objective

  Detect and alert on potential credential dumping activity using Mimikatz, focusing on
 LSASS memory access attempts and registry using **Elastic  kabana With the [Endpoint security integration](https://www.elastic.co/guide/en/security/current/install-endpoint.html)** enabled, you can explore those new events using generic KQL

## Detection Logic / Query
```sql
event.category : ("file" or "registry")
  and event.action : ("open" or "query")
```

## Sample Alert Screenshot

## Logs or Sample Event

## Detection Status
