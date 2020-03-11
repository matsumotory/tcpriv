# tcpriv
tcp separate privilege on TCP using task_struct.

## Quick setup

- install vagrant

- setup build enviroment

```
vagrant up
```

all setup phase was provisioned automatically by `misc/provision.sh` such as installing packages, setup kernel module enviroment, building kernel module and insmod/rmmod tcpriv as a kernel module..

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
