k8s-okta-auth
==================

This application runs inside a Kubernetes cluster and will take a Okta SAML assertion request and generate a Kubernetes x509 client certificate or service account for the user. The user can then easily download it's configuration from the webinterface.

Please note that the accounts created is not directly connected to Okta in any way from Kubernetes' perspective. Okta is merely used to generate these accounts for users that has been assigned the application in Okta. Kubernetes will never ask Okta about anything.

This has both upsides and downsides to it.
Downside is that you will need to handle RBAC and account deletion manually or through a custom automated process.
Upside is that you will not need to do any OIDC/Webhook configuration in your cluster as x509 client certs and service accounts is supported by most providers.
Another good thing is that users/k8s will not need to ask any 3rd party service for authentication once the account has been generated.

## Why is this practical

Manually creating accounts and distributing certificates or accesstokens does not scale very well in larger organizations, and can also be very insecure if not done right.
Also being dependant on 3rd party services for active authenitcation (Webhook/OIDC) is not always desireable and often requires additional client applications and configuration.

Having Okta handling the account creation and user configuration makes all this alot easier.

## When to use x509 client certificates or ServiceAccount-mode

x509 client certificates is what is the default and what should be used in most cases.
The generated x509 client cert will contain all groups the user is assigned to in Okta which can be used in roles/RBAC.
Note that your cluster must support the CertificateSigningRequest API for this to work.

Service accounts on the other hand does not support having groups assigned to them and is intended to be used by applications and services that interact with the cluster.

## EKS support

EKS supports serviceaccounts and IAM authentication, but not x509 client certificates at the time of writing this.

You can use this application with EKS clusters in service account mode.
It's a bit of a hack since service accounts isn't really intended for normal users, but it serves it purpose and works fine.

## How to deploy
Configure settings in helm/values.yaml for your environment.

```
  helm upgrade --wait --namespace=kube-system  --install --recreate-pods -f ./helm/values.yaml okta-authenticate ./helm/charts/k8s-okta-auth
```

###### Required configuration environment variables

| Env                    | Description                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| CLUSTER_NAME           | Name of the Kubernetes cluster
| MASTER_URL             | URL for the cluster Kubernetes API (used in generated config)
| DEFAULT_NAMESPACE      |

## Endpoints
| Endpoint                                             | Description                 |
| ---------------------------------------------------- |  ---------------------------|
| /saml/acs         |  Endpoint used by Kubernetes to authenticate and verify token  |
| /                 |  User frontpage where you can download your configuration      |
| /kubeconfig       |  Standalone kubeconfig file for the logged in user             |
| /setup_cluster.sh |  Script for adding context to existing global kubeconfig       |
