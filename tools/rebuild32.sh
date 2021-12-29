set -e

docker build -f Dockerfile.x86 --platform linux/386 -t pythia:latest .
rm -rf ninja/*
docker run --platform linux/386 --rm -v "$(pwd)"/:/data -w /data/ninja pythia:latest cmake -G Ninja -DCMAKE_PREFIX_PATH=@Pythia/python-37-embed-linux32 -DUSE_64BIT_BUILD=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
docker run --platform linux/386 --rm -v "$(pwd)"/:/data -w /data/ninja pythia:latest ninja
