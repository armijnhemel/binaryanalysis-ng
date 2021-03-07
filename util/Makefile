CTR_BUILDER=podman
IMAGE_KSV=ksv
IMAGE_KAITAI=kaitai

all: docker-kaitai docker-ksv

docker-ksv:
	$(CTR_BUILDER) image build -t $(IMAGE_KSV) -f Dockerfile.ksv .

docker-kaitai:
	[ -d kaitai_struct ] || git clone --recursive https://github.com/kaitai-io/kaitai_struct.git
	$(CTR_BUILDER) image build -t $(IMAGE_KAITAI) -f Dockerfile.kaitai .
	
