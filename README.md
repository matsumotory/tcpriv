# tcpriv
tcp separate privilege on TCP using task_struct.

## Quick setup

- install vagrant

- setup build enviroment

```
vagrant up
```

all setup phase was provisioned automatically by `misc/provision.sh` such as installing packages, setup kernel module enviroment, building kernel module and insmod/rmmod tcpriv as a kernel module.

- vagrant provision example

```
...
    default:   CC      /home/vagrant/tcpriv/build/kernel_module/tcpriv_module.mod.o
    default:   LD [M]  /home/vagrant/tcpriv/build/kernel_module/tcpriv_module.ko
    default: make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-76-generic'
    default: [63992.606662] tcpriv[info]: open
    default: [63992.611846] tcpriv[info]: close
```


## Build and run

```
vagrant ssh
```

- in ubuntu 18.04

```
cd tcpriv/build
make
sudo insmod tcpriv_module.ko
dmesg | tail
sudo rmmod tcpriv_module.ko
```
