DOCKER_KSV=ksv
DOCKER_KAITAI=kaitai

all: docker-kaitai docker-ksv

docker-ksv:
	docker image build -t $(DOCKER_KSV) -f Dockerfile.ksv .

docker-kaitai:
	[ -d kaitai_struct ] || git clone --recursive https://github.com/kaitai-io/kaitai_struct.git
	docker image build -t $(DOCKER_KAITAI) -f Dockerfile.kaitai .
	
