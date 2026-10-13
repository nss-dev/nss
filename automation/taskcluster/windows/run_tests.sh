#!/usr/bin/env bash

set -v -e -x

# Fetch artifact.
if [ "$TASKCLUSTER_ROOT_URL" = "https://taskcluster.net" ] || [ -z "$TASKCLUSTER_ROOT_URL" ]; then
    url=https://queue.taskcluster.net/v1/task/$TC_PARENT_TASK_ID/artifacts/public/build/dist.7z
else
    url=$TASKCLUSTER_ROOT_URL/api/queue/v1/task/$TC_PARENT_TASK_ID/artifacts/public/build/dist.7z
fi

# --retry-connrefused alone doesn't retry HTTP errors, and the queue
# occasionally answers 503.
wget -t 5 --retry-connrefused --retry-on-http-error=429,500,502,503,504 \
    -w 5 --random-wait $url -O dist.7z
7z x dist.7z

export DIST=${PWD}/dist

cp -a "${VCS_PATH}/nss" .

# Run tests.
cd nss/tests && ./all.sh
