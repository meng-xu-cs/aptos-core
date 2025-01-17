help:
	@echo "available targets: fuzz"

fuzz:
	aptos move audit -vv --language 2.1+ ./ fuzz \
		--include-framework --include-deps
