---
name: translate-estimate-cost
description: Estimate what a TruthForm cross-cloud translation would cost to run on AWS or GCP, beside what the source costs on Azure today, from the translated snapshot, the source's measured usage and the vendors' own price lists. Use when someone asks what the move would cost, wants the target clouds compared on price, or needs a budget before a rebuild.
---

# Estimate the bill on the target

`truthform translate` writes what the target would hold. It knows nothing
of prices, and TruthForm makes no price lookup: it stays offline. This
skill is for the agent putting a number on a translation, with the
vendors' own pricing tools beside TruthForm.

## The rules

1. **Every price comes from the vendor's price list, looked up now.** Never
   from memory: prices change, and differ by region. Record the source
   and the date of each.
2. **Every quantity comes from the snapshot or from a measurement.** What
   the target holds is in the translated snapshot. How much it is used
   (messages, gigabytes, hours) is in the source's billing and metrics.
   A quantity you have neither for is asked for, and the line is left
   open until then. Never fill one in.
3. **Reading the source's bill is the person's to allow.** Usage and cost
   data say a lot about a business. Ask before the first read, say what
   you will read, and read nothing else.
4. **Say what kind of price it is.** A list price is not what a customer
   with a contract, a reservation or a savings plan pays. Label every
   figure, and do not net off a discount you cannot see.
5. **An estimate is a range with its assumptions.** Give low and high
   where usage varies, and list each assumption beside the line it
   moves.
6. **You change nothing.** No resource is created to find its price.

## Tools beside TruthForm

TruthForm's `platforms` tool lists each vendor's MCP servers. For prices:

- **AWS:** the AWS Pricing MCP Server (`awslabs.aws-pricing-mcp-server`),
  over the Price List API. It needs AWS credentials.
- **GCP:** the Cloud Billing API's price lookup (its MCP tool `get_price`,
  or the Catalog API for list prices; the Pricing API returns a billing
  account's own contract prices).
- **Azure**, for the source side: the Azure MCP Server's pricing tool
  (retail prices), and Cost Management for what was actually billed.

If one is not connected, say so and stop at that cloud: do not substitute
a web page or a remembered figure.

## Read the work list

1. **What the target holds:** the translated snapshot, one directory per
   platform under the translation's output, beside `translation.yaml`.
   Count objects by `kind` and read the settings that set a price:

   | Priced by the hour, whether used or not | Where its size is |
   |---|---|
   | `AWS::RDS::DBInstance` | `DBInstanceClass`, `AllocatedStorage`, its engine and edition |
   | `AWS::EKS::Cluster`, `AWS::EKS::Nodegroup` | `InstanceTypes`, `ScalingConfig` |
   | `AWS::EC2::NatGateway`, `AWS::EC2::EIP` | one each; a NAT gateway also bills per gigabyte |
   | `AWS::EC2::VPCEndpoint` | per endpoint and zone, and per gigabyte |
   | Cloud SQL instances, GKE clusters and node pools, Cloud NAT | `tier`, `machineType`, node counts |

   | Priced by use only | What to measure on the source |
   |---|---|
   | `AWS::SQS::Queue`, `AWS::SNS::Topic`, Pub/Sub topics and subscriptions | messages in and out per month, and their size |
   | `AWS::S3::Bucket`, Cloud Storage buckets | gigabytes stored, by tier; requests; gigabytes read out |
   | `AWS::SecretsManager::Secret`, Secret Manager secrets | count (in the snapshot), and reads per month |
   | `AWS::EC2::FlowLog`, subnet flow logs | gigabytes of flow records per month |
   | Container registries | gigabytes of images |
   | Any of them | gigabytes sent to the internet and between zones |

2. **What the translation says about cost:** in `translation.yaml`, the
   `requirements` that say something `is billed` (NAT gateways, interface
   endpoints, flow logs, RDS Extended Support). Each is a line of the
   estimate.
3. **What is not in the estimate at all:** every entry `refused` or `not
   looked at`. A machine, an app service or a backup vault the
   translation does not write still costs something on the target once a
   person rebuilds it. List them under "not priced", never as zero.

## Steps

1. Ask which month stands for normal use, and for leave to read the
   source's cost and metrics for it. Read cost by service, and the
   usage measures in the table above.
2. Build one table per target, a row per kind: quantity, where the
   quantity came from, unit price, where the price came from, monthly
   figure. A month is 730 hours.
3. Add the lines a move adds that a steady month does not: the one-time
   transfer of the data out of Azure (see translate-move-data), and
   running both sides during the cut-over.
4. Put the source's actual bill for the same month beside the totals,
   by the same groups of services.
5. Give the result as: fixed per month, usage per month (low to high),
   one-time, and not priced. Then the three assumptions that move the
   total most.

## Check

- Every row has a quantity source and a price source; no row has a
  figure without both.
- The count of objects priced, plus those listed as free of charge, plus
  those under "not priced", equals the count in the translated snapshot
  and `translation.yaml`: nothing fell between.
- Pricing the source's own usage at Azure's retail prices comes within a
  stated margin of the source's actual bill for that month. If it does
  not, the usage read is wrong or a discount is in play: say which, and
  do not publish the target figure until it is explained.
- Run `truthform translate` again from the same snapshot and map: the
  counts are the same, since the estimate is of that translation and no
  other.

## What this cannot show

What the customer would really pay: contract discounts, reservations,
committed-use and savings plans, support plans and tax are not in a list
price. Nor what usage will be after the move, where an app changes how
it sends or stores. And it prices only what the translation wrote: what
it refused is a cost someone still has to add.
