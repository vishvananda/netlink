DIRS := \
	. \
	nl

DEPS = \
	github.com/vishvananda/netns

uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))
testdirs = $(call uniq,$(foreach d,$(1),$(dir $(wildcard $(d)/*_test.go))))
goroot = $(addprefix ../../../,$(1))
unroot = $(subst ../../../,,$(1))

all: test

$(call goroot,$(DEPS)):
	go get $(call unroot,$@)

.PHONY: $(call testdirs,$(DIRS))
$(call testdirs,$(DIRS)):
	! gofmt -l $@*.go | grep ''
	go test -v github.com/vishvananda/netlink/$@

test: $(call goroot,$(DEPS)) $(call testdirs,$(DIRS))
