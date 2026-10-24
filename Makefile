TOOLCHAIN := .toolchain/fasm2
FASMG     := $(TOOLCHAIN)/fasmg.x64
SOURCES   := $(shell find src -name '*.asm' -o -name '*.inc')
BIN       := build/fasm2crud
KAT       := build/kat

.PHONY: all toolchain run test itest kat up down logs bench clean

all: $(BIN)

toolchain: $(FASMG)

$(FASMG):
	./scripts/fetch-fasm2.sh $(TOOLCHAIN)

$(BIN): $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" src/main.asm $@
	@chmod +x $@

$(KAT): tests/kat/kat.asm $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" tests/kat/kat.asm $@
	@chmod +x $@

kat: $(KAT)
	./$(KAT)

run: $(BIN)
	./$(BIN)

test: $(BIN) $(KAT)
	./$(KAT)
	python3 -I tests/kat/differential.py
	python3 -I tests/kat/differential_input.py
	./tests/smoke.sh

itest: $(BIN)
	./tests/db_integration.sh

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f api

bench:
	./tests/bench.sh

clean:
	rm -rf build
