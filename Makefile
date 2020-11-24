DOCKER_IMAGE = zacharyespiritu/apsi-variants
APSI_DIR     = /apsi

run:
	docker run -ti \
		"${DOCKER_IMAGE}" \
		go run "${APSI_DIR}/main.go"

image:
	docker build -f Dockerfile -t "${DOCKER_IMAGE}" .
