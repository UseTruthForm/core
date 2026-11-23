---
name: translate-sql-tls
description: Handle the minimum TLS version of a SQL Server database that a TruthForm cross-cloud translation cannot match on RDS or Cloud SQL, with the nearest setting, compensating controls, a test and a written exception for the security team. Use when translation.yaml has a loss on properties.minimalTlsVersion or mentions acceptTlsFloor.
---

# SQL Server's minimum TLS version

Azure SQL lets a server refuse TLS below a chosen version. The targets
cannot always say the same:

- **RDS for SQL Server** can turn TLS 1.0 and 1.1 off, and the
  translation does. It cannot refuse TLS 1.2, so a source that took only
  1.3 takes 1.2 and later on RDS.
- **Cloud SQL for SQL Server** has no setting for the oldest version it
  takes. The translation requires encryption on every connection; the
  floor is whatever Google keeps.

The translation reports this as a loss that widens, and fails, until the
map accepts the floor per server. This skill is for the agent helping a
person get from that failure to a decision on record.

## The rules

1. **Accepting a weaker floor is the person's decision**, and their
   security team's. You never add `acceptTlsFloor` to the map yourself.
2. **Measure before accepting.** The key is for a floor that has been
   checked on the target, not assumed.
3. **Change nothing on the source** to make the difference go away.

## Read the work list

In `translation.yaml`, every `entries` item with a loss whose `field` is
`properties.minimalTlsVersion`. The `why` names the source's version,
what the target does instead, and the map key that accepts it
(`databases.<group/server>.acceptTlsFloor`). With `widens: true` it is
not yet accepted.

## Steps

1. **State the difference per server** in one line: what the source
   refused, what the target will take.
2. **Measure the target's real floor**, once the server exists: try a
   connection at each TLS version below the source's minimum, from inside
   the network, with a client or scanner that can pin the version. Record
   which are refused. On Cloud SQL this is the only way to know the floor.
3. **Propose compensating controls**, each as its own approved change:
   - clients pin their own minimum: the driver's or the operating
     system's TLS setting, so no client offers an older version;
   - reach stays as narrow as the source's: the translated security
     groups or firewall rules already limit who can connect. Confirm no
     rule was added since;
   - encryption stays required (`rds.force_ssl` on RDS, `sslMode:
     ENCRYPTED_ONLY` on Cloud SQL): confirm with `truthform diff` that
     neither changed.
4. **Write the exception** for the security team: server, source minimum,
   measured target floor, the vendor's limit in one sentence, the
   controls in place, who accepted it and when, and a date to look again
   (vendors add settings).
5. **Only then** tell the person the map key that records their decision.
   They add it; the next `truthform translate` names the loss without
   failing on it.

## Check

- The measurement in step 2, kept with the exception: versions tried,
  result of each.
- `truthform translate` run again with the person's map: the loss is
  still listed, no longer `widens`.
- `truthform diff` of the target against the translated snapshot: no
  difference on the server or its parameters.

## What this cannot show

That every client pins its minimum: that is each application's own
configuration. List the applications that connect (the security groups'
sources say which networks) so the person can ask their owners.
