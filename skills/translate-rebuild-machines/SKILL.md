---
name: translate-rebuild-machines
description: Rebuild the virtual machines and firewall appliances a TruthForm cross-cloud translation does not write, attach the security groups or network tags the report names for each, and restore the routes through an inspection appliance. Use when translation.yaml has attachments marked "requirement", entries for machines that are "not looked at", or route losses that name an appliance.
---

# Rebuild machines and put their rules back on

`truthform translate` writes networks, routes and every network security
group, but no machine: not a VM, not a scale set, not a firewall
appliance. The rules that guarded each machine are written and waiting.
This skill is for the agent helping a person rebuild the machines and
attach those rules exactly.

## The rules

1. **Creating a machine is the person's decision**: it costs money and
   opens a way in. Propose each one in full and wait for a yes.
2. **A machine carries exactly what the report lists for it.** All of the
   groups or tags in its `carries`, and no other of the translated ones.
   One missing leaves it more open or cut off; one extra lets in what
   Azure kept out. The customer's SOC audits this.
3. **No machine goes up before its rules are known.** If the machine's
   interface is not in `attachments`, stop and ask: do not attach a
   default group.
4. **Do not edit the translated groups, rules or routes.** If a machine
   needs something they do not allow, that is a change to the source or a
   new, separately named rule the person approves. An edited group no
   longer matches its evidence.
5. **No credentials from the old machine.** Keys, passwords and local
   accounts are not copied. The machine gets a role on the target (see
   the translate-grant-access skill).

## Read the work list

In `translation.yaml`:

- `attachments`: every item with `attached: requirement`. `source` is the
  Azure interface or scale set, `to` says which machine it belonged to,
  `nsgs` and `asgs` what guarded it, and `carries` the security groups
  (AWS) or network tags (GCP) that now stand for them.
- `entries` with `state: not looked at` whose `source` is a
  `Microsoft.Compute` type or `Microsoft.Network/azureFirewalls`: the
  machines themselves.
  Their size, image and disks are in the Azure snapshot, not in the
  report.
- `entries` whose losses name an appliance: a route that went `to
  virtual appliance`, an interface that `forwarded traffic for other
  addresses`, a peering that `accepted traffic the peer forwarded`. Each
  says what the target does instead until an appliance is back (on AWS
  the subnet has no route for those destinations; on GCP a deny rule
  keeps them off the default route).

## Rebuild a machine

For each one, propose: instance type nearest the Azure size (say the
difference in CPU and memory), an image the person chooses (an Azure
image does not move; name the publisher's image on the target or ask),
the subnet its interface's subnet became (from the subnet's entry
`targets`), disks by size and type with no data (see translate-move-data),
and the groups or tags from `carries`.

- **AWS:** the security groups go on the instance's network interface. A
  scale set becomes a launch template and an Auto Scaling group; the
  groups go in the template. An EKS node group needs a launch template
  to carry them too, and the report says so where that applies.
- **GCP:** the tags go on the instance or the instance template. Firewall
  rules pick machines by tag, so a tag missing means the rule does not
  apply at all.

## Put an inspection appliance back

1. Rebuild the appliance as a machine, as above. It must forward: turn
   the source/destination check off (AWS) or set `canIpForward` (GCP), as
   the interface's loss says.
2. Its rule set is the vendor's own configuration, not in any snapshot.
   Ask the person for its export; do not write firewall policy yourself.
3. Propose the route the loss describes: the same destinations, next hop
   the appliance. On GCP the deny rule that stood in for it is removed
   only once the route exists; propose both as one change so traffic is
   never open in between.
4. Azure Firewall itself is a managed service with no machine to rebuild.
   Its nearest kin are AWS Network Firewall and Cloud NGFW; moving its
   rules is a rewrite the person owns. Say so and list its rule
   collections from the snapshot.

## Check

- `truthform capture` of the target, then for every item in `attachments`
  with `attached: requirement`, find the machine and compare what it
  carries with `carries`: equal as sets, nothing more, nothing less. Show
  the comparison as a table.
- `truthform diff` of the target against the translated snapshot: the
  translated groups, rules and subnets show no difference. New machines
  and the appliance's route show as `extra`; list them for the person to
  sign off.
- For an appliance, a trace from a machine in a routed subnet to an
  outside address must pass through it (the platform's reachability
  analyser, or a traceroute the person runs).

## What this cannot show

That the software on a rebuilt machine is what ran before, or that an
appliance's own rule set matches the old one. Neither is in a snapshot.
