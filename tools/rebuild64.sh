set -e

docker build -f Dockerfile.x64 -t pythia:latest .
rm -rf ninja/*
docker run --rm -v "$(pwd)"/:/data -w /data/ninja pythia:latest cmake -G Ninja -DCMAKE_PREFIX_PATH=@Pythia/python-37-embed-linux64 -DUSE_64BIT_BUILD=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
docker run --rm -v "$(pwd)"/:/data -w /data/ninja pythia:latest ninja
