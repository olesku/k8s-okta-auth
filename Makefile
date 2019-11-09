LAST_COMMIT_ID:=$(shell git rev-parse --short HEAD)
DOCKER_IMAGE_NAME:=k8s-okta-auth
DOCKER_REGISTRY:=127.0.0.1:32000

all:
	go build -o k8s-okta-auth .

docker: docker-build docker-tag docker-push

docker-build:
	docker build -t $(DOCKER_IMAGE_NAME):$(LAST_COMMIT_ID) .

docker-tag:
	docker tag $(DOCKER_IMAGE_NAME):$(LAST_COMMIT_ID) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(LAST_COMMIT_ID)
	docker tag $(DOCKER_IMAGE_NAME):$(LAST_COMMIT_ID) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):latest

docker-push:
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(LAST_COMMIT_ID)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):latest

microk8s: build-microk8s deploy-microk8s

build-microk8s:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o k8s-okta-auth .
	docker build -f Dockerfile.microk8s -t k8s-okta-auth:latest .
	docker save k8s-okta-auth:latest > image.tar
	microk8s.ctr -n k8s.io image import image.tar
	rm -f image.tar

deploy-microk8s:
	microk8s.helm delete --purge oktapreview-microk8s || true
	microk8s.helm install --wait --debug --namespace=default --name=oktapreview-microk8s -f ./helm/microk8s.yaml ./helm/charts/k8s-okta-auth
	@echo "Useful commands:"
	@echo "  microk8s.kubectl logs -n default --follow --tail=20"
	@echo "  microk8s.kubectl get configmap -n default k8s-okta-auth-oktapreview-microk8s -o yaml"
