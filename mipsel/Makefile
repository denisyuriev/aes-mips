# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
#
# Objects are linked from the parent Makefile. `clean-files` is what
# kernel `make clean` deletes when it descends here.

ifneq ($(KERNELRELEASE),)

clean-files := aes-mips-core.o mul8k.o mul16k.o \
	.aes-mips-core.o.cmd .mul8k.o.cmd .mul16k.o.cmd

else

.PHONY: clean
clean:
	rm -f aes-mips-core.o mul8k.o mul16k.o \
		.aes-mips-core.o.cmd .mul8k.o.cmd .mul16k.o.cmd

endif
