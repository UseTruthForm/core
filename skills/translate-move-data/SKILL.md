---
name: translate-move-data
description: Plan and check the copy of data after a TruthForm cross-cloud translation (Azure to AWS or GCP). Use when translation.yaml has requirements saying blobs, images, secret values, databases or volumes are not copied, and someone asks to move the data or to finish the move.
---

# Move the data a translation leaves behind

`truthform translate` writes configuration only. Buckets are written empty,
registries hold no image, secrets hold no value, and a database server has
no database in it. This skill is for the agent helping a person fill them.

## The rules

1. **You plan and check. The person approves every copy before it runs.**
   A copy reads the source's data and writes to the target, with
   credentials that can do both. Show the plan (what, from where, to
   where, with which tool, how much), and wait for a yes on it.
2. **Never read, print or log a secret's value.** Not in a command's
   output, not in a file you write, not in your reply. Work with names
   only. If a tool would echo a value, do not run it.
3. **The work list is `translation.yaml`, not your memory of the source.**
   Copy what it names. If you find data it does not name, say so and ask.
4. **Copy after the translated snapshot is restored**, so the buckets,
   repositories and servers exist as TruthForm wrote them. Do not create
   them yourself to get ahead: a later restore would find something it did
   not write.
5. **Done means checked**, by the checks below, with the numbers shown to
   the person. A copy tool's exit code is not a check.

## Read the work list

In `translation.yaml`, under `requirements`, find the lines that begin or
contain:

| Phrase in the requirement | What it asks for |
|---|---|
| `Blobs are not copied` | every blob container's contents, into the bucket of the entry's `targets` |
| `Images are not copied` | every image of the registry it names, to the address it names |
| `hold no value` | a value for each secret it lists |
| `then move its data` | one line per database: create it, then move its rows |
| `persistent volumes' data is not moved` | the clusters' volumes |

Each `entries` item says what a source object became (`targets`). Pair
every container, registry, secret and database with its target from there.
An entry with `state: refused` has no target: leave it out and list it.

## Plan each kind

- **Blobs.** One job per container, with the cloud's own transfer service
  (the requirement names them: AWS DataSync or S3 Batch Operations; the
  Storage Transfer Service on GCP). The translation does not carry blob
  versions, metadata, tiers or holds: say which of those the chosen tool
  carries and which it drops. Requirements about a retention lock or a
  legal hold are done after the copy, never before: a locked bucket takes
  no correction.
- **Images.** `crane copy` or `skopeo copy`, by digest, every tag. Do this
  before the cluster's workloads are restored, or they fail to pull.
- **Secret values.** On AWS the person supplies them at restore with
  `--values`; you give them the list of names in the form the requirement
  shows, and they fill in the values where you cannot see them. On GCP
  each value is added as a version after the restore, by the person or by
  a job that reads from where the value is kept. A secret the report says
  was disabled gets no value.
- **Databases.** The requirement names each database and its owner. Plan a
  dump and restore for a small one with a maintenance window, or the
  cloud's database migration service for one that must stay up. The
  person chooses; say what each costs in downtime.
- **Volumes.** Per volume, the application's own backup and restore is
  usually safer than a block copy. Ask what the application supports.

For each job state the size, a time estimate and whether the transfer is
billed (data leaving Azure is).

## Check

| Kind | Check | Passes when |
|---|---|---|
| Blobs | object count and total bytes per container against its bucket; checksums where both sides hold one (an Azure blob has an MD5 only if its uploader set it) | counts and bytes equal; no checksum differs |
| Images | the digest of every tag on both sides | every digest equal |
| Secrets | each listed name has a value on the target (existence only) | none is without one, except those disabled on the source |
| Databases | row count per table, and the migration tool's own validation report | all equal; the report is clean |
| Configuration | `truthform diff` of the target against the translated snapshot | no difference: the copy changed no setting |

## What this cannot show

That a secret's value is the right one (only the application proves that,
by working), and that data written to the source after the copy started
made it across. Say both when you report, and name the cut-over moment the
person chose.
