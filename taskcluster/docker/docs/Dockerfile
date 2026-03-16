# Minimal image for linting NSS documentation.
FROM $DOCKER_IMAGE_PARENT

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    python3-pip \
 && pip3 install sphinx \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get autoremove -y && apt-get clean -y

VOLUME /builds/worker/checkouts

# Set a default command for debugging.
CMD ["/bin/bash", "--login"]
