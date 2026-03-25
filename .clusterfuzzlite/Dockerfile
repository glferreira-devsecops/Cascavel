FROM gcr.io/oss-fuzz-base/base-builder-python

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . $SRC/cascavel
WORKDIR $SRC/cascavel

COPY .clusterfuzzlite/build.sh $SRC/build.sh
