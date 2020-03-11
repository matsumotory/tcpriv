obj-m := tcpriv_module.o tcpriv_test_module.o
clean-files := *.o *.ko *.mod.[co] *~

KERNEL_SRC_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_SRC_DIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNEL_SRC_DIR) M=$(PWD) clean
