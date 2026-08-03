BPF_CLANG ?= clang
# Auto-detect the system include root; Termux uses a non-standard prefix.
BPF_SYSTEM_INCLUDE ?= $(shell for d in /usr/include /data/data/com.termux/files/usr/include; do [ -f "$$d/linux/bpf.h" ] && echo "$$d" && break; done)
BPF_ANDROID_INCLUDE ?= $(shell for d in /usr/include/aarch64-linux-android /data/data/com.termux/files/usr/include/aarch64-linux-android; do [ -d "$$d" ] && echo "$$d" && break; done)
BPF_CFLAGS ?= -target bpfel -O2 -g0
BPF_INCLUDE_FLAGS := -Inative -I$(BPF_SYSTEM_INCLUDE)
ifneq (,$(wildcard $(BPF_ANDROID_INCLUDE)))
BPF_INCLUDE_FLAGS += -I$(BPF_ANDROID_INCLUDE)
endif

SOURCE := native/shared_network.bpf.c
OBJECT := native/shared_network.bpf.o

.PHONY: generate check clean

generate:
	@set -eu; \
	temporary="$$(mktemp "$(OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) \
		-c "$(SOURCE)" -o "$$temporary"; \
	mv "$$temporary" "$(OBJECT)"

check:
	@set -eu; \
	temporary="$$(mktemp "$(OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) \
		-c "$(SOURCE)" -o "$$temporary"; \
	if ! cmp -s "$(OBJECT)" "$$temporary"; then \
		echo "$(OBJECT) is stale; run 'make generate' in this directory" >&2; \
		exit 1; \
	fi

clean:
	rm -f "$(OBJECT)"
