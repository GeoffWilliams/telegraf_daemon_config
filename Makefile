# login to ECR first
# aws ecr get-login-password --region ap-southeast-2 | docker login --username AWS --password-stdin 492737776546.dkr.ecr.ap-southeast-2.amazonaws.com

# .env should define ECR_TAG, eg:
# ECR_TAG=xxx.dkr.ecr.ap-southeast-2.amazonaws.com/theimagename:0.0.xx
include .env
EXTRA_DOCKER_BUILD_ARGS := --network host

# database + api driven config with automatic reloads
dynamic:
	docker build $(EXTRA_DOCKER_BUILD_ARGS) --file Dockerfile.dynamic -t ${ECR_TAG} .
	docker push ${ECR_TAG}

# config file embedded in image
static:
	# telegraf.conf must exist in build directory
	docker build $(EXTRA_DOCKER_BUILD_ARGS) --file Dockerfile.static -t ${ECR_TAG} .
	docker push ${ECR_TAG}
