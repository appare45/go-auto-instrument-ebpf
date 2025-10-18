.PHONY: build run

IMAGE_NAME := demo\:latest
CONTAINER_NAME := demo_container

build:
	docker build -t $(IMAGE_NAME) .

run: build
	docker run -d --rm -p 8080:8080 --name $(CONTAINER_NAME) $(IMAGE_NAME)

stop:
	docker stop $(CONTAINER_NAME) || true
