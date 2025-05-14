.PHONY: build-all clean-data gen-placeholder gen-work

build-all:
	@echo "Building all CLI tools..."
	go build -o ./bin/k8schecker ./cmd/k8schecker
	go build -o ./bin/helmctl    ./cmd/helmctl
	go build -o ./bin/configloader ./cmd/configloader
	go build -o ./bin/backupctl ./cmd/backupctl
	go build -o ./bin/productctl ./cmd/productctl
	@echo "All CLI tools built in ./bin/"

clean-data:
	@echo "Removing generated chart data..."
	rm -rf data/charts/*

gen-placeholder:
	@echo "Generating placeholder chart data..."
	@python3 scripts/generate_sample_charts.py --version-type placeholder

gen-work:
	@echo "Generating working chart data..."
	@python3 scripts/generate_sample_charts.py --version-type working