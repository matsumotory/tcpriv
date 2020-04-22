# tcpriv

#### A Design of Access Control Architecture Separating Privilege Transparently via TCP Connection Based on Process Information

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

## Experiment

#### Remote servers get process information like uid/gid from a client server process transparently

<p align="center">
  <img alt="tcpriv flow" src="https://github.com/matsumotory/tcpriv/blob/master/misc/figures/tcpriv-flow.png?raw=true" width="800">
</p>

#### 1. A remote server (192.168.1.172)

```
# in host
vagrant up
vagrant ssh

# in vagrant VM
cd ~/tcpriv/build/kernel_module
sudo insmod tcpriv_module.ko
tail -f /var/log/kern.log
```

#### 2. A client server (192.168.1.186)

```
# in host
vagrant up
vagrant ssh

# in vagrant VM
cd ~/tcpriv/build/kernel_module
sudo insmod tcpriv_module.ko
telnet 192.168.1.172 22
```

#### 3. A remote server (192.168.1.172)

```
# in vagrant VM
tail -f /var/log/kern.log

Apr 22 02:46:49 vagrant kernel: [0] tcpriv[info]: tcpriv found local in TCP syn packet from 192.168.1.186.
Apr 22 02:46:49 vagrant kernel: [1] tcpriv[info]: tcpriv found client process information: 63889:2000
Apr 22 02:46:49 vagrant kernel: [3] tcpriv[info]: tcpriv found local out TCP syn packet from 192.168.1.172.
```
