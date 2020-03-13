# tcpriv

`tcpriv` separates privilege on TCP using Linux owner and permission information of `task_struct`. `tcpriv` is a kernel module for Linux. We develop `tcpriv` on Ubuntu 18.04. Please see `Vagrantfile` and `misc/provision.sh`.

Now under depelopment.

## Quick setup

- install vagrant

- setup build enviroment

```
vagrant up
```

all setup phase was provisioned automatically by `misc/provision.sh` such as installing packages, setup kernel module enviroment, building kernel module and insmod/rmmod tcpriv as a kernel module.

- vagrant provision example

```
dmesg | tail

[  577.102930] tcpriv[info]: open
[  588.734563] tcpriv[info]: tcpriv found local in TCP syn packet from 10.0.2.2.
[  588.734589] tcpriv[info]: tcpriv found local out TCP syn packet from 10.0.2.15.
[  606.533195] tcpriv[info]: close
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
