---
name: translate-flow-logs
description: Adapt a flow log parser or detection rules written for Azure virtual network flow logs to the AWS VPC Flow Logs and GCP VPC Flow Logs that a TruthForm cross-cloud translation writes. Use when a SIEM, a SOC pipeline or a parser must read flow logs from the translated networks, or translation.yaml lists flow log losses.
---

# Read the target's flow logs as the source's were read

`truthform translate` turns each Azure virtual network flow log into the
target's own: an `AWS::EC2::FlowLog` in one fixed record format, or
`logConfig` on GCP subnetworks. The records are the target's, not
Azure's. This skill is for the agent helping adapt whatever parses them.

The field-by-field table is in TruthForm's guide, section "Flow logs"
(`docs/guide.md`). Read it first; this page is how to use it.

## The rules

1. **Normalise to one record, per cloud, in the parser.** Do not try to
   make a target's log look like Azure's on the wire.
2. **Never invent a field the target does not record.** Where Azure had a
   value and the target has none, the normalised field is empty and
   marked absent, not guessed. A detection that needs it is listed as
   affected.
3. **Do not change the flow log the translation wrote** (its format,
   interval or what it covers) to suit a parser. The AWS format is fixed
   so that its field order can be relied on.
4. **Test on real records from each cloud**, not on records you wrote.

## Read the work list

In `translation.yaml`:

- `entries` whose `source` is a
  `Microsoft.Network/networkWatchers/flowLogs`: `targets` say what logs
  on the target, and `losses` what differs (where records go, retention,
  format, filtering).
- `requirements` that mention flow logs: the bucket policy for delivery
  on AWS, the Logging sink on GCP, the retention to set, and the record
  format line.

Where the records land decides how the pipeline collects them: an S3
bucket the map chose (AWS), or Cloud Logging's `vpc_flows` log, carried on
by a sink (GCP).

## The differences that change detections

| Azure gave | AWS | GCP | What to do |
|---|---|---|---|
| Flow state: begin, continuing, end, denied | no state; `action` (accept or reject) per one-minute window; `tcp-flags` for TCP | no state, no verdict | derive begin and end from SYN and FIN or RST on AWS, TCP only. On GCP, mark state absent |
| Denied flows | `action: REJECT` | an ingress-denied packet is not recorded at all | on GCP, denied-traffic detections need firewall rule logging, which the translation does not turn on: say so and ask |
| Both directions in one tuple | one record per direction | one entry per direction, and a flow between two logged machines is reported by both ends | pair the two; de-duplicate on GCP by reporter |
| The rule that decided | none | none | detections keyed on a rule name are affected; list them |
| Time in milliseconds | a window, `start` and `end` in seconds | RFC 3339 `start_time`, `end_time` | normalise to one clock and keep the window |
| Byte counts | bytes of the packets | payload bytes only | do not compare volumes across clouds without saying so |

## Steps

1. List the fields the existing parser emits and the detections that use
   each.
2. Map each field per cloud from the guide's table. Mark each: same,
   derived (say how), or absent.
3. List every detection that reads an absent or derived field, with what
   it loses. Give this list to the person before writing code: it is the
   SOC's decision whether a weaker detection is acceptable or needs
   another source.
4. Write the parser for the target's record, and tests from real sample
   records the person supplies or the pipeline collects.

## Check

- The same test traffic (one allowed connection, one denied, one long
  transfer) made on Azure and on the target parses to normalised records
  that agree on addresses, ports, protocol, direction and verdict, within
  the limits listed above.
- Every field marked absent is empty in the output, never filled.
- `truthform diff` of the target against the translated snapshot: the
  flow log is as written.

## What this cannot show

That no detection silently lost meaning. The list in step 3 is the
record of what changed; the SOC signs it.
