# tcpriv
tcp separate privilege on TCP using task_struct.

## Quic setup

- install vagrant

- setup build enviroment

```
vagrant up
```

all setup phase was provisioned automatically by `misc/provision.sh` such as installing packages, setup kernel module enviroment and build kernel module.

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
