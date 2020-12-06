#!/bin/bash

APSI_DIR=/apsi

go build -o "${APSI_DIR}/apsi" "${APSI_DIR}/main.go"

"${APSI_DIR}/apsi" -cpuprofile="apsi.prof"

go tool pprof "${APSI_DIR}/apsi" apsi.prof
