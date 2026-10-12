clean:
	cargo clean

readme:
	cli/update-readme.sh

build:
	cargo build --release

cli:
	cargo build --release -p async-hwi-cli --bin hwi
