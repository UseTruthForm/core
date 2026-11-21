package translate

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/usetruthform/core/internal/snapshot"
)

// goAzure is the Azure side: everything the other families' fixtures
// hold, so a manifest can name a registry, a queue, a secret, a bucket
// and a database server, translated or not.
func goAzure() snapshot.Snapshot {
	s := snapshot.Snapshot{Platform: "azure", Policy: "default"}
	for _, f := range []snapshot.Snapshot{fixture(), acrFixture(), kvFixture(), stFixture(), dbFixture()} {
		s.Objects = append(s.Objects, f.Objects...)
	}
	return s
}

// goMaps: one map per messaging destination, each with every other class
// chosen.
func goMaps() map[string]Map {
	a, g := dbMaps()["aws"], dbMaps()["gcp"]
	a.Sessions, a.Names = "fifo", map[string]string{"rg/shop/legacy.feed": "legacy-feed"}
	a.Destinations.Messaging, a.Destinations.Registry, a.Destinations.Secrets, a.Destinations.Storage = "sqs-sns", "ecr", "secret-manager", "buckets"
	g.Sessions, g.Secrets = "ordering", kvMaps()["gcp"].Secrets
	g.Destinations.Messaging, g.Destinations.Registry, g.Destinations.Secrets, g.Destinations.Storage = "pubsub", "artifact-registry", "secret-manager", "buckets"
	r := a
	r.Sessions, r.RabbitMQ = "single-active-consumer", &RabbitMQ{Namespace: "messaging", Replicas: 3}
	r.Destinations.Messaging = "rabbitmq"
	return map[string]Map{"aws": a, "gcp": g, "rabbitmq": r}
}

func k8s(apiVersion, kind, ns, name string, labels map[string]any, rest map[string]any) snapshot.Object {
	md := map[string]any{"name": name}
	if ns != "" {
		md["namespace"] = ns
	}
	if labels != nil {
		md["labels"] = labels
	}
	body := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": md}
	for k, v := range rest {
		body[k] = v
	}
	return snapshot.Object{Body: body}
}

// goKubeFixture is a made-up capture of the source cluster: where Flux
// starts, a namespace nobody put in Git, and the skips that name what
// each source applies.
func goKubeFixture() snapshot.Snapshot {
	self := map[string]any{"kustomize.toolkit.fluxcd.io/name": "flux-system", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}
	pod := func(image string, env ...any) map[string]any {
		return map[string]any{"containers": []any{map[string]any{"name": "main", "image": image, "env": env}}}
	}
	ks := snapshot.FluxKustomizationReason
	return snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
		k8s("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "flux-system", self, map[string]any{"spec": map[string]any{
			"interval": "10m", "path": "./clusters/prod", "prune": true, "sourceRef": map[string]any{"kind": "GitRepository", "name": "flux-system"}}}),
		k8s("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "flux-system", self, map[string]any{"spec": map[string]any{
			"interval": "1m", "url": "ssh://git@ssh.dev.azure.com/v3/madeup/shop/fleet", "ref": map[string]any{"branch": "main"}}}),
		k8s("apps/v1", "Deployment", "legacy", "worker", nil, map[string]any{"spec": map[string]any{"template": map[string]any{
			"metadata": map[string]any{"labels": map[string]any{"app": "worker", "aadpodidbinding": "worker"}},
			"spec": pod("shopacr.azurecr.io/legacy/worker:7",
				map[string]any{"name": "QUEUE", "value": "Endpoint=sb://shop.servicebus.windows.net/;SharedAccessKeyName=worker;SharedAccessKey={{truthform|withheld}};EntityPath=orders"},
				map[string]any{"name": "FEED", "value": "Endpoint=sb://shop.servicebus.windows.net/;EntityPath=nosuch"})}}}),
		k8s("batch/v1", "CronJob", "legacy", "sweep", nil, map[string]any{"spec": map[string]any{"schedule": "0 3 * * *",
			"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": pod("mcr.microsoft.com/azure-cli:2.60.0")}}}}}),
		k8s("v1", "ConfigMap", "legacy", "settings", nil, map[string]any{"data": map[string]any{
			"app.conf": "vault = https://shop.vault.azure.net/secrets/db-password\nevents = evh.servicebus.windows.net\n"}}),
		k8s("v1", "PersistentVolumeClaim", "legacy", "data", nil, map[string]any{"spec": map[string]any{"storageClassName": "managed-csi"}}),
		k8s("storage.k8s.io/v1", "StorageClass", "", "fast", nil, map[string]any{"provisioner": "disk.csi.azure.com", "parameters": map[string]any{"skuName": "Premium_LRS"}}),
		k8s("servicebus.azure.com/v1api20211101", "NamespacesQueue", "legacy", "refunds", nil, map[string]any{"spec": map[string]any{"owner": map[string]any{"name": "shop"}}}),
		k8s("apps/v1", "Deployment", "tools", "kept", map[string]any{"kustomize.toolkit.fluxcd.io/name": "tools", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"},
			map[string]any{"spec": map[string]any{"template": map[string]any{"spec": pod("pubimages.azurecr.io/tools/kept:2")}}}),
	}, Coverage: []snapshot.Coverage{
		{Resource: "apps/v1/deployments", Kind: "Deployment", Captured: 2},
		{Resource: "core/v1/configmaps", Kind: "ConfigMap", Captured: 1},
		{Resource: "core/v1/serviceaccounts", Kind: "ServiceAccount"},
		{Resource: "keda.sh/v1alpha1/scaledobjects", Kind: "ScaledObject"},
		{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Kind: "Kustomization", Captured: 1},
		{Resource: "helm.toolkit.fluxcd.io/v2/helmreleases", Kind: "HelmRelease"},
	}, Skips: []snapshot.Skip{
		{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "flux-system", Name: "apps", Reason: ks("flux-system", "flux-system")},
		{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "flux-system", Name: "tenants", Reason: ks("flux-system", "flux-system")},
		{Resource: "apps/v1/deployments", Namespace: "shop", Name: "web", Reason: ks("flux-system", "apps")},
		{Resource: "keda.sh/v1alpha1/scaledobjects", Namespace: "shop", Name: "web-orders", Reason: ks("flux-system", "apps")},
		{Resource: "core/v1/serviceaccounts", Namespace: "shop", Name: "web", Reason: ks("flux-system", "apps")},
		{Resource: "core/v1/configmaps", Namespace: "shop", Name: "web-env-7m2k9tb5c4", Reason: ks("flux-system", "apps")},
		{Resource: "helm.toolkit.fluxcd.io/v2/helmreleases", Namespace: "shop", Name: "worker", Reason: ks("flux-system", "apps")},
		{Resource: "apps/v1/deployments", Namespace: "shop", Name: "worker", Reason: snapshot.FluxHelmReleaseReason("shop", "worker")},
		{Resource: "apps/v1/deployments", Namespace: "tenants", Name: "api", Reason: ks("flux-system", "tenants")},
		{Resource: "apps/v1/deployments", Namespace: "ops", Name: "tool", Reason: snapshot.FluxHelmReleaseReason("ops", "tool")},
		{Resource: "apps/v1/deployments", Namespace: "billing", Name: "api", Reason: snapshot.ArgoCDReason("billing")},
		{Resource: "core/v1/pods", Namespace: "legacy", Name: "*", Reason: snapshot.OwnedReason("Deployment", "worker")},
	}}
}

const goRepoDir = "testdata/gitops/repo"

// goRun translates the Azure fixture for one of goMaps and adds the
// GitOps report from the inputs given.
func goRun(t *testing.T, name string, kube, repo bool) (Result, string) {
	t.Helper()
	m := goMaps()[name]
	res, err := Translate(goAzure(), m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	var in GitOpsInput
	if kube {
		k := goKubeFixture()
		in.Kube = &k
	}
	if repo {
		in.Dir = goRepoDir
	}
	vars, err := GitOps(goAzure(), m, &res, in)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(vars)
}

func TestGitOpsGolden(t *testing.T) {
	for _, name := range []string{"aws", "gcp", "rabbitmq"} {
		res, vars := goRun(t, name, true, true)
		got, err := yaml.Marshal(map[string]any{"gitops": res.Report.GitOps})
		if err != nil {
			t.Fatal(err)
		}
		for file, body := range map[string]string{"gitops-" + name + ".yaml": string(got), "gitops-" + name + "-variables.yaml": vars} {
			path := filepath.Join("testdata", "gitops", file)
			if *update {
				if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to write it)", err)
			}
			if string(want) != body {
				t.Errorf("%s differs from what the translation writes now (run with -update and read the diff)", path)
			}
		}
	}
}

// goLines is the change list, one line a reference: where, its state,
// what it names, and what that is on the target.
func goLines(r Result) []string {
	var out []string
	for _, x := range r.Report.GitOps.References {
		where := "snapshot " + x.Object
		if x.File != "" {
			where = x.File + ":" + strconv.Itoa(x.Line)
		}
		state := string(x.State)
		if x.NotApplied {
			state += " (not applied)"
		}
		out = append(out, where+" | "+state+" | "+x.Names+" | "+x.Target)
	}
	return out
}

// The change list on AWS, with SQS and SNS for messaging: every
// reference, in order.
var goWantAWS = []string{
	"apps/base/charts.yaml:29 | change | shopacr.azurecr.io/shop/worker | {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr/shop/worker",
	"apps/base/charts.yaml:33 | check | Azure Workload Identity client ID (annotation azure.workload.identity/client-id) | eks.amazonaws.com/role-arn: <the role's ARN> (IAM roles for service accounts), or no annotation and an EKS Pod Identity association of the role with this service account",
	"apps/base/charts.yaml:35 | check | AKS storage class managed-csi-premium | a StorageClass of the EBS CSI driver (provisioner ebs.csi.aws.com; ebs.csi.eks.amazonaws.com on EKS Auto Mode)",
	"apps/base/charts.yaml:37 | check | ingress class webapprouting.kubernetes.azure.com | an IngressClass of the AWS Load Balancer Controller (controller ingress.k8s.aws/alb) with its alb.ingress.kubernetes.io/ annotations, or the class of whichever ingress controller the cluster runs",
	"apps/base/charts.yaml:41 | change | shop.servicebus.windows.net | no host of its own: each queue is https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/<queue>, each topic arn:aws:sns:eu-west-1:{{truthform|account|self|id}}:<topic>",
	"apps/base/charts.yaml:43 | change | open.vault.azure.net/secrets/token | open/token",
	"apps/base/shop/deployment.yaml:15 | check | Azure Workload Identity pod label azure.workload.identity/use | remove it",
	"apps/base/shop/deployment.yaml:20 | change | shopacr.azurecr.io/shop/web:1.4.2 | {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr/shop/web:1.4.2",
	"apps/base/shop/deployment.yaml:23 | change | shop.servicebus.windows.net | no host of its own: each queue is https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/<queue>, each topic arn:aws:sns:eu-west-1:{{truthform|account|self|id}}:<topic>",
	"apps/base/shop/deployment.yaml:25 | change | shopassets.blob.core.windows.net/images | shopassets-images",
	"apps/base/shop/deployment.yaml:27 | change | shopassets.blob.core.windows.net | no endpoint of its own: each container is a bucket (images -> shopassets-images, ledger -> shopassets-ledger, records -> shopassets-records)",
	"apps/base/shop/deployment.yaml:29 | no translation | shopassets.file.core.windows.net | ",
	"apps/base/shop/deployment.yaml:31 | change | shop-pg.postgres.database.azure.com | the endpoint RDS gives DB instance shop-pg when it is created",
	"apps/base/shop/deployment.yaml:33 | no translation | legacy-pg.postgres.database.azure.com | ",
	"apps/base/shop/deployment.yaml:35 | no translation | shopcache.redis.cache.windows.net | ",
	"apps/base/shop/deployment.yaml:37 | check | login.microsoftonline.com | the target's own sign-in",
	"apps/base/shop/deployment.yaml:41 | no translation | partner.azurecr.io/tools/proxy@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | ",
	"apps/base/shop/deployment.yaml:43 | change | pubimages.azurecr.io/static:latest | {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/pubimages/static:latest",
	"apps/base/shop/deployment.yaml:45 | change | 9lives.azurecr.io/odd:1 | {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/9lives/odd:1",
	"apps/base/shop/deployment.yaml:61 | check | AKS storage class managed-csi | a StorageClass of the EBS CSI driver (provisioner ebs.csi.aws.com; ebs.csi.eks.amazonaws.com on EKS Auto Mode)",
	"apps/base/shop/deployment.yaml:73 | check | AKS storage class azurefile-csi | a StorageClass of the Amazon EFS CSI driver",
	"apps/base/shop/identity.yaml:7 | check | Azure Workload Identity client ID (annotation azure.workload.identity/client-id) | eks.amazonaws.com/role-arn: <the role's ARN> (IAM roles for service accounts), or no annotation and an EKS Pod Identity association of the role with this service account",
	"apps/base/shop/identity.yaml:8 | check | Azure Workload Identity setting azure.workload.identity/tenant-id | remove it",
	"apps/base/shop/network.yaml:7 | change | annotation service.beta.kubernetes.io/azure-load-balancer-internal | service.beta.kubernetes.io/aws-load-balancer-scheme: internal (AWS Load Balancer Controller; the in-tree controller reads service.beta.kubernetes.io/aws-load-balancer-internal: \"true\")",
	"apps/base/shop/network.yaml:8 | check | annotation service.beta.kubernetes.io/azure-load-balancer-internal-subnet | its counterpart, if any, among the AWS Load Balancer Controller's Service annotations",
	"apps/base/shop/network.yaml:22 | check | annotation appgw.ingress.kubernetes.io/ssl-redirect | an IngressClass of the AWS Load Balancer Controller (controller ingress.k8s.aws/alb) with its alb.ingress.kubernetes.io/ annotations, or the class of whichever ingress controller the cluster runs",
	"apps/base/shop/network.yaml:24 | check | ingress class azure-application-gateway | an IngressClass of the AWS Load Balancer Controller (controller ingress.k8s.aws/alb) with its alb.ingress.kubernetes.io/ annotations, or the class of whichever ingress controller the cluster runs",
	"apps/base/shop/scaling.yaml:10 | change | KEDA azure-servicebus trigger on queue orders (namespace shop) | type: aws-sqs-queue; metadata: queueURL: https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/orders, awsRegion: \"eu-west-1\", queueLength: \"20\", scaleOnInFlight: \"false\", activationQueueLength: \"2\"",
	"apps/base/shop/scaling.yaml:18 | change | KEDA azure-servicebus trigger on topic events, subscription audit | type: aws-sqs-queue; metadata: queueURL: https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/events-audit, awsRegion: \"eu-west-1\", queueLength: \"5\", scaleOnInFlight: \"false\"",
	"apps/base/shop/scaling.yaml:23 | no translation | KEDA azure-servicebus trigger on topic events, subscription fraud (namespace shop) | ",
	"apps/base/shop/scaling.yaml:28 | no translation | KEDA azure-servicebus trigger on queue refunds (namespace shop) | ",
	"apps/base/shop/scaling.yaml:32 | no translation | KEDA azure-servicebus trigger on queue orders-.* (namespace shop) | ",
	"apps/base/shop/scaling.yaml:37 | no translation | KEDA trigger azure-queue | ",
	"apps/base/shop/scaling.yaml:55 | check | KEDA pod identity provider azure-workload | podIdentity.provider: aws (with roleArn, or identityOwner: workload)",
	"apps/base/shop/scaling.yaml:60 | change | Key Vault shop secret api-abc123 | spec.awsSecretManager: region: eu-west-1, secrets[].name: shop/api-abc123",
	"apps/base/shop/secrets.yaml:7 | change | Secrets Store provider azure, Key Vault shop | provider: aws; parameters: region: \"eu-west-1\", objects: a list of objectName and objectType (each is listed below)",
	"apps/base/shop/secrets.yaml:16 | change | Key Vault shop secret db-password | objectName: \"shop/db-password\", objectType: \"secretsmanager\", objectAlias: \"db-password\"",
	"apps/base/shop/secrets.yaml:19 | change | Key Vault shop secret api-abc123 | objectName: \"shop/api-abc123\", objectType: \"secretsmanager\", objectAlias: \"API_KEY\"",
	"apps/base/shop/secrets.yaml:24 | no translation | Key Vault shop key signing | ",
	"apps/base/shop/secrets.yaml:27 | no translation | Key Vault shop secret not-there | ",
	"apps/base/shop/secrets.yaml:43 | change | External Secrets store of Key Vault open | provider: aws: service: SecretsManager, region: eu-west-1",
	"apps/base/shop/secrets.yaml:63 | change | Key Vault open secret token | open/token",
	"apps/base/shop/secrets.yaml:66 | no translation | Key Vault open cert frontdoor | ",
	"apps/base/shop/secrets.yaml:68 | check | the secrets of Key Vault open it finds by name or tag | the same search over names that start with open/",
	"apps/base/shop/web.env:2 | change | shopassets.blob.core.windows.net/ledger | shopassets-ledger",
	"apps/prod/kustomization.yaml:7 | change | shopacr.azurecr.io/shop/web | {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr/shop/web",
	"apps/staging/preview.yaml:17 | no translation (not applied) | stagingonly.azurecr.io/shop/preview:0.1 | ",
	"charts/local/templates/deployment.yaml:10 | change (not applied) | shopacr.azurecr.io | {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr",
	"clusters/prod/apps.yaml:15 | change | shopacr.azurecr.io/charts | {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr/charts",
	"snapshot ConfigMap legacy/settings | no translation | evh.servicebus.windows.net | ",
	"snapshot ConfigMap legacy/settings | change | shop.vault.azure.net/secrets/db-password | shop/db-password",
	"snapshot Deployment legacy/worker | check | AAD Pod Identity label aadpodidbinding | remove it",
	"snapshot Deployment legacy/worker | change | shop.servicebus.windows.net (EntityPath orders) | https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/orders",
	"snapshot Deployment legacy/worker | no translation | shop.servicebus.windows.net (EntityPath nosuch) | ",
	"snapshot Deployment legacy/worker | change | shopacr.azurecr.io/legacy/worker:7 | {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr/legacy/worker:7",
	"snapshot Deployment tools/kept | change | pubimages.azurecr.io/tools/kept:2 | {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/pubimages/tools/kept:2",
	"snapshot NamespacesQueue legacy/refunds | no translation | an object of the API group servicebus.azure.com | ",
	"snapshot PersistentVolumeClaim legacy/data | check | AKS storage class managed-csi | a StorageClass of the EBS CSI driver (provisioner ebs.csi.aws.com; ebs.csi.eks.amazonaws.com on EKS Auto Mode)",
	"snapshot StorageClass fast | check | provisioner disk.csi.azure.com | a StorageClass of the EBS CSI driver (provisioner ebs.csi.aws.com; ebs.csi.eks.amazonaws.com on EKS Auto Mode)",
}

// On GCP, the lines that differ from AWS's.
var goWantGCP = []string{
	"apps/base/charts.yaml:29 | change | shopacr.azurecr.io/shop/worker | europe-west1-docker.pkg.dev/{{truthform|project}}/shopacr/shop/worker",
	"apps/base/charts.yaml:33 | check | Azure Workload Identity client ID (annotation azure.workload.identity/client-id) | iam.gke.io/gcp-service-account: <service account>@{{truthform|project}}.iam.gserviceaccount.com, or no annotation and roles granted to the Kubernetes service account itself (principal://iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/{{truthform|project}}.svc.id.goog/subject/ns/<namespace>/sa/<name>)",
	"apps/base/charts.yaml:35 | check | AKS storage class managed-csi-premium | a StorageClass of the Persistent Disk CSI driver (provisioner pd.csi.storage.gke.io)",
	"apps/base/charts.yaml:37 | check | ingress class webapprouting.kubernetes.azure.com | GKE's Ingress controller (annotation kubernetes.io/ingress.class: gce, or gce-internal) or the Gateway API, or the class of whichever ingress controller the cluster runs",
	"apps/base/charts.yaml:41 | change | shop.servicebus.windows.net | no host of its own: topics and subscriptions are named under projects/{{truthform|project}}",
	"apps/base/charts.yaml:43 | change | open.vault.azure.net/secrets/token | open_token",
	"apps/base/shop/deployment.yaml:20 | change | shopacr.azurecr.io/shop/web:1.4.2 | europe-west1-docker.pkg.dev/{{truthform|project}}/shopacr/shop/web:1.4.2",
	"apps/base/shop/deployment.yaml:23 | change | shop.servicebus.windows.net | no host of its own: topics and subscriptions are named under projects/{{truthform|project}}",
	"apps/base/shop/deployment.yaml:31 | change | shop-pg.postgres.database.azure.com | the address Cloud SQL gives instance shop-pg when it is created",
	"apps/base/shop/deployment.yaml:43 | change | pubimages.azurecr.io/static:latest | europe-west1-docker.pkg.dev/{{truthform|project}}/pubimages/static:latest",
	"apps/base/shop/deployment.yaml:45 | no translation | 9lives.azurecr.io/odd:1 | ",
	"apps/base/shop/deployment.yaml:61 | check | AKS storage class managed-csi | a StorageClass of the Persistent Disk CSI driver (provisioner pd.csi.storage.gke.io)",
	"apps/base/shop/deployment.yaml:73 | check | AKS storage class azurefile-csi | a StorageClass of the Filestore CSI driver (provisioner filestore.csi.storage.gke.io)",
	"apps/base/shop/identity.yaml:7 | check | Azure Workload Identity client ID (annotation azure.workload.identity/client-id) | iam.gke.io/gcp-service-account: <service account>@{{truthform|project}}.iam.gserviceaccount.com, or no annotation and roles granted to the Kubernetes service account itself (principal://iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/{{truthform|project}}.svc.id.goog/subject/ns/<namespace>/sa/<name>)",
	"apps/base/shop/network.yaml:7 | change | annotation service.beta.kubernetes.io/azure-load-balancer-internal | networking.gke.io/load-balancer-type: \"Internal\" (or spec.loadBalancerClass: networking.gke.io/l4-regional-internal, GKE 1.33.1 and later)",
	"apps/base/shop/network.yaml:8 | check | annotation service.beta.kubernetes.io/azure-load-balancer-internal-subnet | its counterpart, if any, among GKE's LoadBalancer Service parameters",
	"apps/base/shop/network.yaml:22 | check | annotation appgw.ingress.kubernetes.io/ssl-redirect | GKE's Ingress controller (annotation kubernetes.io/ingress.class: gce, or gce-internal) or the Gateway API, or the class of whichever ingress controller the cluster runs",
	"apps/base/shop/network.yaml:24 | check | ingress class azure-application-gateway | GKE's Ingress controller (annotation kubernetes.io/ingress.class: gce, or gce-internal) or the Gateway API, or the class of whichever ingress controller the cluster runs",
	"apps/base/shop/scaling.yaml:10 | change | KEDA azure-servicebus trigger on queue orders (namespace shop) | type: gcp-pubsub; metadata: subscriptionName: projects/{{truthform|project}}/subscriptions/orders, mode: SubscriptionSize, value: \"20\", activationValue: \"2\"",
	"apps/base/shop/scaling.yaml:18 | change | KEDA azure-servicebus trigger on topic events, subscription audit | type: gcp-pubsub; metadata: subscriptionName: projects/{{truthform|project}}/subscriptions/events-audit, mode: SubscriptionSize, value: \"5\"",
	"apps/base/shop/scaling.yaml:55 | check | KEDA pod identity provider azure-workload | podIdentity.provider: gcp",
	"apps/base/shop/scaling.yaml:60 | change | Key Vault shop secret api-abc123 | spec.gcpSecretManager: secrets[].id: shop_api-abc123",
	"apps/base/shop/secrets.yaml:7 | change | Secrets Store provider azure, Key Vault shop | provider: gcp; parameters: secrets: a list of resourceName and path (each is listed below)",
	"apps/base/shop/secrets.yaml:16 | change | Key Vault shop secret db-password | resourceName: \"projects/{{truthform|project}}/secrets/shop_db-password/versions/latest\", path: \"db-password\"",
	"apps/base/shop/secrets.yaml:19 | change | Key Vault shop secret api-abc123 | resourceName: \"projects/{{truthform|project}}/secrets/shop_api-abc123/versions/latest\", path: \"API_KEY\"",
	"apps/base/shop/secrets.yaml:43 | change | External Secrets store of Key Vault open | provider: gcpsm: projectID: {{truthform|project}}",
	"apps/base/shop/secrets.yaml:63 | change | Key Vault open secret token | open_token",
	"apps/base/shop/secrets.yaml:68 | check | the secrets of Key Vault open it finds by name or tag | the same search over names that start with open_",
	"apps/prod/kustomization.yaml:7 | change | shopacr.azurecr.io/shop/web | europe-west1-docker.pkg.dev/{{truthform|project}}/shopacr/shop/web",
	"charts/local/templates/deployment.yaml:10 | change (not applied) | shopacr.azurecr.io | europe-west1-docker.pkg.dev/{{truthform|project}}/shopacr",
	"clusters/prod/apps.yaml:15 | change | shopacr.azurecr.io/charts | europe-west1-docker.pkg.dev/{{truthform|project}}/shopacr/charts",
	"snapshot ConfigMap legacy/settings | change | shop.vault.azure.net/secrets/db-password | shop_db-password",
	"snapshot Deployment legacy/worker | change | shop.servicebus.windows.net (EntityPath orders) | projects/{{truthform|project}}/subscriptions/orders",
	"snapshot Deployment legacy/worker | change | shopacr.azurecr.io/legacy/worker:7 | europe-west1-docker.pkg.dev/{{truthform|project}}/shopacr/legacy/worker:7",
	"snapshot Deployment tools/kept | change | pubimages.azurecr.io/tools/kept:2 | europe-west1-docker.pkg.dev/{{truthform|project}}/pubimages/tools/kept:2",
	"snapshot PersistentVolumeClaim legacy/data | check | AKS storage class managed-csi | a StorageClass of the Persistent Disk CSI driver (provisioner pd.csi.storage.gke.io)",
	"snapshot StorageClass fast | check | provisioner disk.csi.azure.com | a StorageClass of the Persistent Disk CSI driver (provisioner pd.csi.storage.gke.io)",
}

// With RabbitMQ in the cluster (the rest on AWS), the lines that differ.
var goWantRabbit = []string{
	"apps/base/charts.yaml:41 | change | shop.servicebus.windows.net | shop.messaging.svc, port 5672",
	"apps/base/shop/deployment.yaml:23 | change | shop.servicebus.windows.net | shop.messaging.svc, port 5672",
	"apps/base/shop/scaling.yaml:10 | change | KEDA azure-servicebus trigger on queue orders (namespace shop) | type: rabbitmq; metadata: queueName: orders, mode: QueueLength, value: \"20\", activationValue: \"2\"",
	"apps/base/shop/scaling.yaml:18 | change | KEDA azure-servicebus trigger on topic events, subscription audit | type: rabbitmq; metadata: queueName: events.audit, mode: QueueLength, value: \"5\"",
	"snapshot Deployment legacy/worker | change | shop.servicebus.windows.net (EntityPath orders) | orders",
}

func goDiff(t *testing.T, what string, got, want []string) {
	t.Helper()
	if reflect.DeepEqual(got, want) {
		return
	}
	in := func(l []string, s string) bool {
		for _, x := range l {
			if x == s {
				return true
			}
		}
		return false
	}
	for _, g := range got {
		if !in(want, g) {
			t.Errorf("%s: not expected: %s", what, g)
		}
	}
	for _, w := range want {
		if !in(got, w) {
			t.Errorf("%s: missing: %s", what, w)
		}
	}
	if !t.Failed() {
		t.Errorf("%s: the same lines in another order", what)
	}
}

func TestGitOpsChangeList(t *testing.T) {
	aws, _ := goRun(t, "aws", true, true)
	goDiff(t, "aws", goLines(aws), goWantAWS)
	for name, want := range map[string][]string{"gcp": goWantGCP, "rabbitmq": goWantRabbit} {
		r, _ := goRun(t, name, true, true)
		var differs []string
		for i, l := range goLines(r) {
			if i >= len(goWantAWS) || l != goWantAWS[i] {
				differs = append(differs, l)
			}
		}
		if len(goLines(r)) != len(goWantAWS) {
			t.Errorf("%s: %d references, aws has %d: the same places name the same things", name, len(goLines(r)), len(goWantAWS))
		}
		goDiff(t, name, differs, want)
	}
}

func goRef(t *testing.T, r Result, where, names string) GitOpsRef {
	t.Helper()
	for _, x := range r.Report.GitOps.References {
		if (x.File == where || where == "" && x.File == "") && x.Names == names {
			return x
		}
	}
	t.Fatalf("no reference to %s in %q", names, where)
	return GitOpsRef{}
}

// What applies each reference, where it is, and the variable that holds
// its target.
func TestGitOpsWhereAndBy(t *testing.T) {
	r, _ := goRun(t, "aws", true, true)
	const apps = "Flux Kustomization flux-system/apps"
	for _, c := range []struct {
		file, names, object, by, field, variable string
		line                                     int
	}{
		{"apps/base/shop/deployment.yaml", "shopacr.azurecr.io/shop/web:1.4.2", "Deployment shop/web", apps, "spec.template.spec.containers[0].image", "registry_shopacr", 20},
		{"apps/base/shop/scaling.yaml", "KEDA azure-servicebus trigger on queue orders (namespace shop)", "ScaledObject shop/web-orders", apps, "spec.triggers[0]", "servicebus_shop_queue_orders", 10},
		{"apps/base/shop/identity.yaml", "Azure Workload Identity client ID (annotation azure.workload.identity/client-id)", "ServiceAccount shop/web", apps, `metadata.annotations["azure.workload.identity/client-id"]`, "", 7},
		// A line of a block scalar is counted from where the block starts.
		{"apps/base/shop/secrets.yaml", "Key Vault shop secret api-abc123", "SecretProviderClass shop/web", apps, "spec.parameters.objects", "keyvault_shop_secret_api_abc123", 19},
		{"apps/base/charts.yaml", "open.vault.azure.net/secrets/token", "HelmRelease shop/worker", apps, "spec.values.config", "keyvault_open_secret_token", 43},
		{"apps/base/charts.yaml", "shopacr.azurecr.io/shop/worker", "HelmRelease shop/worker", apps, "spec.values.image.repository", "registry_shopacr", 29},
		// A file that is no manifest: a generator's input, by its line.
		{"apps/base/shop/web.env", "shopassets.blob.core.windows.net/ledger", "", apps, "", "storage_shopassets_ledger", 2},
		// The Kustomization that fills a variable in is where the value is.
		{"clusters/prod/apps.yaml", "shopacr.azurecr.io/charts", "Kustomization flux-system/apps", "Flux Kustomization flux-system/flux-system", "spec.postBuild.substitute.chart_registry", "registry_shopacr", 15},
		// In the snapshot: kept though a source applies it, and applied by nothing.
		{"", "pubimages.azurecr.io/tools/kept:2", "Deployment tools/kept", "Flux Kustomization flux-system/tools", "spec.template.spec.containers[0].image", "registry_pubimages", 0},
		{"", "shopacr.azurecr.io/legacy/worker:7", "Deployment legacy/worker", goBySnapshot, "spec.template.spec.containers[0].image", "registry_shopacr", 0},
	} {
		x := goRef(t, r, c.file, c.names)
		if x.Object != c.object || x.AppliedBy != c.by || x.Field != c.field || x.Variable != c.variable || x.Line != c.line {
			t.Errorf("%s in %q: object %q, applied by %q, field %q, variable %q, line %d", c.names, c.file, x.Object, x.AppliedBy, x.Field, x.Variable, x.Line)
		}
	}
	// A file of another cluster's overlay, and a chart's template no
	// Kustomization reaches: listed, marked, and not counted.
	for _, c := range [][2]string{{"apps/staging/preview.yaml", "stagingonly.azurecr.io/shop/preview:0.1"}, {"charts/local/templates/deployment.yaml", "shopacr.azurecr.io"}} {
		if x := goRef(t, r, c[0], c[1]); !x.NotApplied || x.AppliedBy != goByNothing {
			t.Errorf("%s: not applied %v, by %q", c[0], x.NotApplied, x.AppliedBy)
		}
	}
	if n := r.Report.GitOps.Counts(); n[GitOpsNone] != 14 || n[GitOpsChange] != 26 || n[GitOpsCheck] != 17 || n[""] != 2 {
		t.Errorf("counts: %v", n)
	}
}

// Why a reference has no translation is the translation's own reason,
// or that the thing is not in the Azure snapshot.
func TestGitOpsNoTranslation(t *testing.T) {
	aws, _ := goRun(t, "aws", true, true)
	gcp, _ := goRun(t, "gcp", true, true)
	for _, c := range []struct {
		r           Result
		file, names string
		why         string
	}{
		{aws, "apps/base/shop/deployment.yaml", "partner.azurecr.io/tools/proxy@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "registry partner is not in the Azure snapshot"},
		{gcp, "apps/base/shop/deployment.yaml", "9lives.azurecr.io/odd:1", "Microsoft.ContainerRegistry/registries rg/9lives was refused: \"9lives\" is not a repository ID"},
		{aws, "apps/base/shop/deployment.yaml", "legacy-pg.postgres.database.azure.com", "data/legacy-pg was refused: the map gives no instance class"},
		{aws, "apps/base/shop/deployment.yaml", "shopassets.file.core.windows.net", "only blob containers are translated"},
		{aws, "apps/base/shop/deployment.yaml", "shopcache.redis.cache.windows.net", "the service behind this name is not translated"},
		{aws, "apps/base/shop/scaling.yaml", "KEDA azure-servicebus trigger on topic events, subscription fraud (namespace shop)", "rg/shop/events/fraud was refused: rule big is a SQL filter"},
		{aws, "apps/base/shop/scaling.yaml", "KEDA azure-servicebus trigger on queue refunds (namespace shop)", "queue refunds of Service Bus namespace shop is not in the Azure snapshot"},
		{aws, "apps/base/shop/scaling.yaml", "KEDA azure-servicebus trigger on queue orders-.* (namespace shop)", "regular expression"},
		{aws, "apps/base/shop/scaling.yaml", "KEDA trigger azure-queue", "no rule translates a KEDA azure-queue trigger"},
		{aws, "apps/base/shop/secrets.yaml", "Key Vault shop key signing", "only a vault's secrets are translated"},
		{aws, "apps/base/shop/secrets.yaml", "Key Vault shop secret not-there", "is not in the Azure snapshot"},
		{aws, "apps/base/shop/secrets.yaml", "Key Vault open cert frontdoor", "only a vault's secrets are translated"},
		{aws, "", "evh.servicebus.windows.net", "Event Hubs and Relay answer under the same domain"},
		{aws, "", "shop.servicebus.windows.net (EntityPath nosuch)", "neither a queue nor a topic"},
		{aws, "", "an object of the API group servicebus.azure.com", "makes or configures an Azure resource"},
	} {
		x := goRef(t, c.r, c.file, c.names)
		if x.State != GitOpsNone || x.Target != "" || !strings.Contains(x.Why, c.why) {
			t.Errorf("%s: %s, target %q, why %q", c.names, x.State, x.Target, x.Why)
		}
	}
	if !aws.Report.Failed() {
		t.Error("references with no translation, and the run is not failed")
	}
}

// What a workload names without saying which namespace it is in is taken
// only when one namespace has it.
func TestGitOpsEntityWithoutItsNamespace(t *testing.T) {
	s := goAzure()
	m := goMaps()["aws"]
	res, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	x := newGoIndex(s, m, &res)
	if e, why := x.entity("", "orders", "", ""); why != "" || e.ns != "shop" {
		t.Errorf("one namespace has orders: %+v, %q", e, why)
	}
	x.queues["other/orders"] = "Microsoft.ServiceBus/namespaces/queues rg/other/orders"
	if _, why := x.entity("", "orders", "", ""); !strings.Contains(why, "in 2 Service Bus namespaces") || !strings.Contains(why, "other, shop") {
		t.Errorf("two namespaces have orders: %q", why)
	}
	if _, why := x.entity("", "", "events", ""); why != "" {
		t.Errorf("a topic alone: %q", why)
	}
	// A secret of a vault that is not there: it is the vault that is missing.
	if got := x.secret("nosuch", "a"); got.state != GitOpsNone || got.why != "Key Vault nosuch is not in the Azure snapshot" {
		t.Errorf("a secret of a vault that is not in the snapshot: %+v", got)
	}
}

// What the snapshot leaves out is said, source by source, and so is
// everything else this cannot see.
func TestGitOpsSaysWhatItDidNotSee(t *testing.T) {
	source := func(r Result, id string) GitOpsSource {
		t.Helper()
		for _, s := range r.Report.GitOps.Sources {
			if s.Source == id {
				return s
			}
		}
		t.Fatalf("no source %s", id)
		return GitOpsSource{}
	}
	said := func(r Result, part string) {
		t.Helper()
		for _, s := range r.Report.GitOps.NotSeen {
			if strings.Contains(s, part) {
				return
			}
		}
		t.Errorf("not said: %s\n%s", part, strings.Join(r.Report.GitOps.NotSeen, "\n"))
	}
	// The snapshot alone: it names the sources, and holds nothing of
	// what they apply.
	k, _ := goRun(t, "aws", true, false)
	for id, left := range map[string]int{"Flux Kustomization flux-system/apps": 5, "Flux Kustomization flux-system/flux-system": 2,
		"Flux Kustomization flux-system/tenants": 1, "Flux HelmRelease shop/worker": 1, "Flux HelmRelease ops/tool": 1, "Argo CD application billing": 1} {
		if s := source(k, id); s.Checked != goNotAvailable || s.LeftOut != left || s.Why == "" {
			t.Errorf("%s with the snapshot alone: %+v", id, s)
		}
	}
	if s := source(k, "Flux Kustomization flux-system/tools"); s.Checked != goInSnapshot {
		t.Errorf("a source whose objects the snapshot holds: %+v", s)
	}
	if n := k.Report.GitOps.NotAvailable(); n != 6 {
		t.Errorf("%d sources not available", n)
	}
	said(k, "6 source(s) whose content was not available to check: Argo CD application billing, Flux HelmRelease ops/tool, Flux HelmRelease shop/worker, Flux Kustomization flux-system/apps, Flux Kustomization flux-system/flux-system, Flux Kustomization flux-system/tenants.")
	said(k, "No checkout of the repository Flux reads was given (--gitops)")
	said(k, "Secret values are in neither input")
	said(k, "Only Flux's sources are followed")
	for _, x := range k.Report.GitOps.References {
		if x.File != "" {
			t.Errorf("a reference in a file, and no file was read: %+v", x)
		}
	}
	if want := []GitOpsNamespace{{Namespace: "legacy", Workloads: []string{"CronJob sweep", "Deployment worker"}}}; !reflect.DeepEqual(k.Report.GitOps.NotInGit, want) {
		t.Errorf("not in Git: %+v", k.Report.GitOps.NotInGit)
	}

	// Both: what the files hold is checked, and what they do not is named.
	b, _ := goRun(t, "aws", true, true)
	apps := source(b, "Flux Kustomization flux-system/apps")
	if apps.Checked != goFiles || apps.Path != "./apps/prod" || apps.LeftOut != 5 || apps.Found != 4 || !reflect.DeepEqual(apps.NotFound, []string{"ConfigMap shop/web-env-7m2k9tb5c4"}) {
		t.Errorf("apps: %+v", apps)
	}
	if s := source(b, "Flux HelmRelease shop/worker"); s.Checked != goValuesOnly || !strings.Contains(s.Why, "1 valuesFrom reference(s)") {
		t.Errorf("a HelmRelease is read by its values: %+v", s)
	}
	if s := source(b, "Flux Kustomization flux-system/tenants"); s.Checked != goNotAvailable || !strings.Contains(s.Why, "its path ./tenants is not in the --gitops directory (it reads GitRepository flux-system/tenants") {
		t.Errorf("a Kustomization of another repository: %+v", s)
	}
	if n := b.Report.GitOps.NotAvailable(); n != 3 {
		t.Errorf("%d sources not available", n)
	}
	for _, part := range []string{
		"3 source(s) whose content was not available to check: Argo CD application billing, Flux HelmRelease ops/tool, Flux Kustomization flux-system/tenants.",
		"1 HelmRelease(s) were read by their values only",
		"1 object(s) the capture left to a Kustomization are not in the files read for it",
		"read as written, not built",
		"2 reference(s) are in files this cluster's Flux does not apply",
		"1 value(s) hold a ${...}",
		"1 kustomize resource(s) are fetched from a URL",
		"1 file(s) are not YAML as written (a chart's templates): read line by line for Azure host names only: charts/local/templates/deployment.yaml.",
		"1 ExternalSecret(s) read a store that is not among what was read",
		"What the applications' own code and images name",
	} {
		said(b, part)
	}

	// The files alone: every Kustomization they define is followed, the
	// other cluster's too, and that is said.
	f, _ := goRun(t, "aws", false, true)
	said(f, "No Kubernetes snapshot was given (--kube)")
	said(f, "Without a Kubernetes snapshot every Flux Kustomization the files define was followed")
	if x := goRef(t, f, "apps/staging/preview.yaml", "stagingonly.azurecr.io/shop/preview:0.1"); x.NotApplied || x.AppliedBy != "Flux Kustomization flux-system/apps" {
		t.Errorf("the other cluster's overlay, with no snapshot to tell them apart: %+v", x)
	}
	if x := goRef(t, f, "apps/base/shop/deployment.yaml", "shopacr.azurecr.io/shop/web:1.4.2"); x.AppliedBy != "Flux Kustomization flux-system/apps" {
		t.Errorf("a base two overlays share: %+v", x)
	}
	if len(f.Report.GitOps.NotInGit) != 0 {
		t.Errorf("not in Git, with no snapshot: %+v", f.Report.GitOps.NotInGit)
	}
}

// goTree writes a made-up repository and reads it.
func goTree(t *testing.T, files map[string]string) *goRepo {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r, err := goReadRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func goFluxYAML(name, path string) string {
	return "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: " + name + "\n  namespace: flux-system\nspec:\n  path: " + path + "\n  targetNamespace: team\n  sourceRef:\n    kind: GitRepository\n    name: fleet\n"
}

// Which files a Kustomization applies, as Flux builds its path.
func TestGitOpsFollowsAPathAsFluxDoes(t *testing.T) {
	const cm = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"
	r := goTree(t, map[string]string{
		"flux/plain.yaml":   goFluxYAML("plain", "./plain"),
		"flux/listed.yaml":  goFluxYAML("listed", "listed"),
		"flux/gone.yaml":    goFluxYAML("gone", "./nowhere"),
		"flux/escapes.yaml": goFluxYAML("escapes", "../elsewhere"),
		// No kustomization.yaml: every manifest in the tree, and a
		// directory with its own is built as one.
		"plain/a.yaml":                     cm,
		"plain/deep/b.yml":                 cm,
		"plain/deep/notes.txt":             "notes",
		"plain/own/kustomization.yaml":     "resources:\n  - in.yaml\n",
		"plain/own/in.yaml":                cm,
		"plain/own/out.yaml":               cm,
		"listed/kustomization.yaml":        "resources:\n  - one.yaml\n  - ../shared\n  - https://example.org/remote.yaml\n  - ../../outside\npatches:\n  - path: patch.yaml\n  - patch: |-\n      - op: remove\n        path: /x\nhelmCharts:\n  - name: chart\n",
		"listed/one.yaml":                  cm,
		"listed/patch.yaml":                cm,
		"listed/unlisted.yaml":             cm,
		"shared/kustomization.yml":         "resources:\n  - s.yaml\n",
		"shared/s.yaml":                    cm,
		".git/config":                      "url = https://shopacr.azurecr.io",
		"plain/deep/big.yaml":              cm + "# " + strings.Repeat("x", goMaxFileSize),
		"plain/deep/binary.yaml":           "a\x00b",
		"plain/deep/template.yaml":         "a: {{ .Values.b }}\n{{- if .Values.c }}\nc: 1\n{{- end }}\n",
		"listed/kustomization.yaml.backup": cm,
	})
	r.attribute(nil)
	got := map[string][]string{}
	for _, f := range r.flux {
		got[f.name] = goSortedSet(f.files)
		if f.files == nil {
			got[f.name] = []string{f.why}
		}
	}
	want := map[string][]string{
		"plain":   {"plain/a.yaml", "plain/deep/b.yml", "plain/deep/big.yaml", "plain/deep/binary.yaml", "plain/deep/template.yaml", "plain/own/in.yaml", "plain/own/kustomization.yaml"},
		"listed":  {"listed/kustomization.yaml", "listed/one.yaml", "listed/patch.yaml", "shared/kustomization.yml", "shared/s.yaml"},
		"gone":    {"its path ./nowhere is not in the --gitops directory (it reads GitRepository flux-system/fleet, which may be another repository)"},
		"escapes": {"its path ../elsewhere leaves the repository"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("files:\n got %v\nwant %v", got, want)
	}
	if r.remote != 1 || r.inflated != 1 || !reflect.DeepEqual(r.outside, []string{"listed/kustomization.yaml: ../../outside"}) {
		t.Errorf("remote %d, inflated %d, outside %v", r.remote, r.inflated, r.outside)
	}
	if !reflect.DeepEqual(r.skipped, []string{"plain/deep/big.yaml"}) || !reflect.DeepEqual(r.asText, []string{"plain/deep/template.yaml"}) {
		t.Errorf("skipped %v, as text %v", r.skipped, r.asText)
	}
	if _, ok := r.files[".git/config"]; ok {
		t.Error("the repository's own .git was read")
	}
	// A file that names no namespace takes its Kustomization's.
	for _, d := range r.files["plain/a.yaml"] {
		if d.object() != "ConfigMap team/x" || d.appliedBy() != "Flux Kustomization flux-system/plain" {
			t.Errorf("%s, applied by %s", d.object(), d.appliedBy())
		}
	}
	if d := r.files["listed/unlisted.yaml"][0]; d.appliedBy() != goByNothing || d.notApplied {
		t.Errorf("a file its kustomization does not list: %s, not applied %v", d.appliedBy(), d.notApplied)
	}
}

// A host name is found whole, and only under Azure's domains.
func TestGitOpsHosts(t *testing.T) {
	s := goAzure()
	m := goMaps()["aws"]
	res, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	find := func(v string) []string {
		sc := &goScan{x: newGoIndex(s, m, &res), stores: map[string]string{}}
		sc.doc(&goDoc{body: map[string]any{"data": map[string]any{"v": v}}, lines: map[string]int{}, blocks: map[string]bool{}})
		var out []string
		for _, r := range sc.refs {
			out = append(out, r.What+" "+r.Names+" "+string(r.State))
		}
		return out
	}
	for v, want := range map[string][]string{
		"shopacr.azurecr.io":                                       {"image shopacr.azurecr.io change"},
		"SHOPACR.azurecr.io/Team/App:1":                            {"image SHOPACR.azurecr.io/Team/App:1 change"},
		"docker://shopacr.azurecr.io/a/b:1.0, and more":            {"image shopacr.azurecr.io/a/b:1.0 change"},
		"xshopacr.azurecr.io/a":                                    {"image xshopacr.azurecr.io/a no translation"},
		"shopacr.azurecr.io.example.org/a":                         nil,
		"shopacr.azurecr.iox":                                      nil,
		"my-shopacr.azurecr.io":                                    {"image my-shopacr.azurecr.io no translation"},
		"https://dev.azure.com/madeup/shop/_git/fleet":             nil,
		"mcr.microsoft.com/azure-cli":                              nil,
		"shopacr.azurecr.io/a shopacr.azurecr.io/a":                {"image shopacr.azurecr.io/a change"},
		"https://shopassets.blob.core.windows.net/images/a.png":    {"storage shopassets.blob.core.windows.net/images change"},
		"abfss://raw@shoplake.dfs.core.windows.net/":               {"storage shoplake.dfs.core.windows.net change"},
		"https://shopassets.blob.core.windows.net/catalog":         {"storage shopassets.blob.core.windows.net/catalog no translation"},
		"https://nosuch.blob.core.windows.net/x":                   {"storage nosuch.blob.core.windows.net/x no translation"},
		"shop-sql.database.windows.net,1433":                       {"database shop-sql.database.windows.net change"},
		"shop-my.mysql.database.azure.com":                         {"endpoint shop-my.mysql.database.azure.com no translation"},
		"https://shop.vault.azure.net/secrets/legacy/0123":         {"secret shop.vault.azure.net/secrets/legacy change"},
		"https://shop.vault.azure.net/keys/signing":                {"secret shop.vault.azure.net change"},
		"https://nosuch.vault.azure.net":                           {"secret nosuch.vault.azure.net no translation"},
		"sb://shop.servicebus.windows.net/;EntityPath=events":      {"messaging shop.servicebus.windows.net (EntityPath events) change"},
		"https://login.microsoftonline.com/common":                 {"identity login.microsoftonline.com check"},
		"shop-aks-0123.hcp.westeurope.azmk8s.io":                   {"endpoint shop-aks-0123.hcp.westeurope.azmk8s.io no translation"},
		"shop.privatelink.vaultcore.azure.net and nothing else":    {"endpoint shop.privatelink.vaultcore.azure.net no translation"},
		"a plain sentence about windows.net and azure.com itself.": nil,
	} {
		if got := find(v); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}

// A connection string is named by its host: no part of a value that may
// be a credential reaches the report or the variables file.
func TestGitOpsNeverRepeatsAValue(t *testing.T) {
	for _, name := range []string{"aws", "gcp", "rabbitmq"} {
		res, vars := goRun(t, name, true, true)
		b, err := yaml.Marshal(res.Report.GitOps)
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range []string{"SharedAccessKey=", "SharedAccessKeyName", "truthform|withheld", "00000000-0000-0000-0000-0000000000aa"} {
			if strings.Contains(string(b), part) || strings.Contains(vars, part) {
				t.Errorf("%s: %q is repeated", name, part)
			}
		}
	}
}

// The variables file is a ConfigMap Flux's post-build substitution can
// read: names it takes, the target's names as values, nothing else.
func TestGitOpsVariables(t *testing.T) {
	name := regexp.MustCompile(`^[_[:alpha:]][_[:alpha:][:digit:]]*$`) // Flux's own rule
	want := map[string]map[string]string{
		"aws": {
			"cloud": "aws", "region": "eu-west-1",
			"registry_shopacr":                          "{{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr",
			"registry_9lives":                           "{{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/9lives",
			"servicebus_shop_queue_orders":              "https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/orders",
			"servicebus_shop_queue_payments":            "https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/payments.fifo",
			"servicebus_shop_queue_legacy_feed":         "https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/legacy-feed",
			"servicebus_shop_topic_events":              "arn:aws:sns:eu-west-1:{{truthform|account|self|id}}:events",
			"servicebus_shop_subscription_events_audit": "https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/events-audit",
			"keyvault_shop_secret_db_password":          "shop/db-password",
			"storage_shopassets_images":                 "shopassets-images",
		},
		"gcp": {
			"cloud": "gcp", "region": "europe-west1",
			"registry_shopacr":                          "europe-west1-docker.pkg.dev/{{truthform|project}}/shopacr",
			"registry_9lives":                           "",
			"servicebus_shop_queue_orders":              "projects/{{truthform|project}}/subscriptions/orders",
			"servicebus_shop_topic_events":              "projects/{{truthform|project}}/topics/events",
			"servicebus_shop_subscription_events_audit": "projects/{{truthform|project}}/subscriptions/events-audit",
			"keyvault_shop_secret_db_password":          "shop_db-password",
			"storage_shopassets_images":                 "shopassets-images",
		},
		"rabbitmq": {
			"cloud":                                     "aws",
			"servicebus_shop_queue_orders":              "orders",
			"servicebus_shop_queue_legacy_feed":         "legacy-feed",
			"servicebus_shop_topic_events":              "events",
			"servicebus_shop_subscription_events_audit": "events.audit",
			"registry_shopacr":                          "{{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr",
		},
	}
	for dest, keys := range want {
		_, vars := goRun(t, dest, false, true)
		var cm struct {
			APIVersion string            `json:"apiVersion"`
			Kind       string            `json:"kind"`
			Metadata   map[string]string `json:"metadata"`
			Data       map[string]string `json:"data"`
		}
		if err := yaml.UnmarshalStrict([]byte(vars), &cm); err != nil {
			t.Fatalf("%s: %v\n%s", dest, err, vars)
		}
		if cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || !reflect.DeepEqual(cm.Metadata, map[string]string{"name": "truthform-translation"}) {
			t.Errorf("%s: %s %s %v", dest, cm.APIVersion, cm.Kind, cm.Metadata)
		}
		for k, v := range cm.Data {
			if !name.MatchString(k) {
				t.Errorf("%s: Flux does not take %q as a variable's name", dest, k)
			}
			if v == "" || strings.Contains(v, "azure") || strings.Contains(v, "windows.net") {
				t.Errorf("%s: %s is %q", dest, k, v)
			}
		}
		for k, v := range keys {
			if cm.Data[k] != v {
				t.Errorf("%s: %s is %q, want %q", dest, k, cm.Data[k], v)
			}
		}
		// What was refused has no name on the target, so no variable.
		for _, k := range []string{"servicebus_shop_subscription_events_fraud", "storage_shopassets_catalog", "keyvault_gone_secret_orphan"} {
			if _, ok := cm.Data[k]; ok {
				t.Errorf("%s: %s is refused, and has a variable", dest, k)
			}
		}
		for _, part := range []string{"  # on Azure: shopacr.azurecr.io\n  registry_shopacr:", "  # on Azure: queue orders in Service Bus namespace shop\n", "spec.postBuild.substituteFrom", "$${name}", "kustomize.toolkit.fluxcd.io/substitute: disabled", "is not known offline"} {
			if !strings.Contains(vars, part) {
				t.Errorf("%s: the file does not say %q", dest, part)
			}
		}
	}
	// Two Azure names that become one variable's name: the later takes
	// a number, and neither is lost.
	s := goAzure()
	s.Objects = append(s.Objects, az("Microsoft.ContainerRegistry/registries", "rg", "shop.acr", map[string]any{"location": "westeurope"}),
		az("Microsoft.ContainerRegistry/registries", "rg", "shop-acr", map[string]any{"location": "westeurope"}))
	m := goMaps()["aws"]
	res := Result{Report: Report{Entries: []Entry{
		{Source: "Microsoft.ContainerRegistry/registries rg/shop.acr", State: Mapped, Targets: []string{awsRepoTmpl + " shop.acr"}},
		{Source: "Microsoft.ContainerRegistry/registries rg/shop-acr", State: Mapped, Targets: []string{awsRepoTmpl + " shop-acr"}}}}}
	var got []string
	for _, v := range newGoIndex(s, m, &res).variables() {
		got = append(got, v.name+"="+v.was)
	}
	if want := []string{"registry_shop_acr=shop-acr.azurecr.io", "registry_shop_acr_2=shop.acr.azurecr.io"}; !reflect.DeepEqual(got, want) {
		t.Errorf("colliding names: %v", got)
	}
}

// What fails the run: a reference with no translation in something the
// cluster applies. Not one that only needs editing, not a source that
// could not be read, and not a file the cluster's Flux does not apply.
func TestGitOpsFailed(t *testing.T) {
	deploy := func(image string) string {
		return "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: shop\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: " + image + "\n"
	}
	// An Azure snapshot whose translation has nothing to say against it.
	s := snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.ContainerRegistry/registries", "rg", "pubimages", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Basic"},
			"properties": map[string]any{"adminUserEnabled": false, "publicNetworkAccess": "Enabled"}})}}
	m := acrMaps()["aws"]
	root := goKubeFixture()
	root.Objects, root.Skips = root.Objects[:2], nil
	for _, c := range []struct {
		name   string
		files  map[string]string
		kube   *snapshot.Snapshot
		failed bool
	}{
		{"a reference that has a translation", map[string]string{"a.yaml": deploy("pubimages.azurecr.io/a:1")}, nil, false},
		{"a reference to check", map[string]string{"a.yaml": deploy("example.org/a:1") + "      serviceAccountName: web\n---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: web\n  annotations:\n    azure.workload.identity/client-id: x\n"}, nil, false},
		{"a reference with no translation", map[string]string{"a.yaml": deploy("partner.azurecr.io/a:1")}, nil, true},
		{"the same, in a file this cluster's Flux does not apply", map[string]string{"other/a.yaml": deploy("partner.azurecr.io/a:1"), "clusters/prod/b.yaml": deploy("pubimages.azurecr.io/a:1")}, &root, false},
		{"the same, in a file it applies", map[string]string{"clusters/prod/a.yaml": deploy("partner.azurecr.io/a:1")}, &root, true},
		{"a source that could not be read", map[string]string{"clusters/prod/x.yaml": goFluxYAML("gone", "./nowhere")}, &root, false},
	} {
		res, err := Translate(s, m, targets(t))
		if err != nil {
			t.Fatal(err)
		}
		if res.Report.Failed() {
			t.Fatalf("the translation fails by itself: %+v", res.Report.Entries)
		}
		dir := t.TempDir()
		for name, body := range c.files {
			p := filepath.Join(dir, filepath.FromSlash(name))
			os.MkdirAll(filepath.Dir(p), 0o755)
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := GitOps(s, m, &res, GitOpsInput{Kube: c.kube, Dir: dir}); err != nil {
			t.Fatal(err)
		}
		if len(res.Report.GitOps.References) == 0 && c.name != "a source that could not be read" {
			t.Errorf("%s: nothing was found", c.name)
		}
		if res.Report.Failed() != c.failed {
			t.Errorf("%s: failed %v\n%+v", c.name, res.Report.Failed(), res.Report.GitOps.References)
		}
	}
	// Not a Kubernetes snapshot, and a directory that is not there.
	res := Result{}
	if _, err := GitOps(s, m, &res, GitOpsInput{Kube: &s}); err == nil || !strings.Contains(err.Error(), "--kube reads a Kubernetes snapshot; this one is azure") {
		t.Errorf("an Azure snapshot as --kube: %v", err)
	}
	if _, err := GitOps(s, m, &res, GitOpsInput{Dir: filepath.Join(t.TempDir(), "nowhere")}); err == nil {
		t.Error("a directory that is not there is read")
	}
}

// The same inputs give the same report, whatever order maps are walked in.
func TestGitOpsDeterministic(t *testing.T) {
	a, av := goRun(t, "rabbitmq", true, true)
	for i := 0; i < 5; i++ {
		b, bv := goRun(t, "rabbitmq", true, true)
		if !reflect.DeepEqual(a.Report.GitOps, b.Report.GitOps) || av != bv {
			t.Fatal("two runs differ")
		}
	}
}

// With no GitOps input the report has no such section, and nothing fails
// for it.
func TestGitOpsIsOptIn(t *testing.T) {
	res, err := Translate(goAzure(), goMaps()["aws"], targets(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := yaml.Marshal(res.Report)
	if res.Report.GitOps != nil || strings.Contains(string(b), "gitops") {
		t.Error("a report with a GitOps section nobody asked for")
	}
}
