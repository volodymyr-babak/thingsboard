#!/bin/bash
#
# Copyright © 2016-2025 The Thingsboard Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

source compose-utils.sh

COMPOSE_VERSION=$(composeVersion) || exit $?

ADDITIONAL_COMPOSE_EDQS_ARGS=$(additionalComposeEdqsArgs) || exit $?

# Name of the service to use for curl requests
CURL_SERVICE="curl-client"

# Function to check readiness within the Docker container
run_compose_cmd() {
  local cmd=$1

  case $COMPOSE_VERSION in
      V2)
          docker compose $cmd
      ;;
      V1)
          docker-compose --compatibility $cmd
      ;;
      *)
          # unknown option
      ;;
  esac
}

# Function to check readiness within the Docker container
check_ready() {
  local service=$1
  local url="http://$service:8080/api/edqs/ready"
  echo "Checking readiness for $service from $CURL_SERVICE using url $url..."

  while true; do
    COMPOSE_ARGS="-f docker-compose.curl.yml exec -T $CURL_SERVICE curl -s -o /dev/null -w "%{http_code}" $url"
    response=$(run_compose_cmd "$COMPOSE_ARGS")

    if [ "$response" -eq 200 ]; then
      echo "$service is ready."
      return 0
    else
      echo "$service is not ready, waiting..."
      sleep 1
    fi
  done
}

# Restart a specific service
restart_service() {
  local service=$1
  echo "Restarting $service..."

  COMPOSE_ARGS="${ADDITIONAL_COMPOSE_EDQS_ARGS} stop $service"
  run_compose_cmd "$COMPOSE_ARGS"

  COMPOSE_ARGS="${ADDITIONAL_COMPOSE_EDQS_ARGS} start $service"
  run_compose_cmd "$COMPOSE_ARGS"

  check_ready $service
}

# Main process for rolling updates
echo "Starting rolling restart process..."

COMPOSE_ARGS="\
      -f docker-compose.curl.yml \
      up -d"

run_compose_cmd "$COMPOSE_ARGS"

# First, ensure tb-edqs1 is ready, then restart tb-edqs2
check_ready "tb-edqs1"
restart_service "tb-edqs2"

# Ensure tb-edqs2 is ready, then restart tb-edqs1
check_ready "tb-edqs2"
restart_service "tb-edqs1"

echo "Rolling restart process completed."