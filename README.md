# tcpriv

#### A Design of Access Control Architecture Separating Privilege Transparently via TCP Connection Based on Process Information

`tcpriv` separates privilege on TCP using Linux owner and permission information of `task_struct`. `tcpriv` is a kernel module for Linux. We develop `tcpriv` on Ubuntu 18.04. Please see `Vagrantfile` and `misc/provision.sh`.

Now under depelopment.

## Quick setup

- install vagrant

- setup build enviroment

```
# Support mutliple vm building
vagrant up

# on one terminal
vagrant ssh client

# on another terminal
vagrant ssh server
```

all setup phase was provisioned automatically by `misc/provision.sh` such as installing packages, setup kernel module enviroment, building kernel module and insmod/rmmod tcpriv as a kernel module.

- vagrant provision example

```
dmesg | tail

[430] tcpriv[info]: open
[543] tcpriv[info]: found local in TCP syn packet from 192.168.1.186.
[566] tcpriv[info]: found client process info: uid=1000 gid=1000
[587] tcpriv[info]: found local out TCP syn packet from 192.168.1.172.
```

## Experiment

#### Remote servers get process information like uid/gid from a client server process transparently

<p align="center">
  <img alt="tcpriv flow" src="https://github.com/matsumotory/tcpriv/blob/master/misc/figures/tcpriv-flow.png?raw=true" width="800">
</p>

#### 1. A remote server (192.168.0.3)

```
# in host
vagrant up
vagrant ssh server

# in vagrant server VM
cd ~/tcpriv/build/kernel_module
sudo insmod tcpriv_module.ko
tail -f /var/log/kern.log
```

#### 2. A client server (192.168.0,2)

```
# in host
vagrant ssh client

# in vagrant client VM
cd ~/tcpriv/build/kernel_module
sudo insmod tcpriv_module.ko
telnet 192.168.0.3 22

# check uid/gid
ps -o cmd,uid,gid | grep telnet
telnet     1000  1000
```

#### 3. The remote server (192.168.0.3)

```
# in host
vagrant ssh server

# in vagrant server VM
tail -f /var/log/kern.log

Apr 22 05:16:23 vagrant kernel: [543] tcpriv[info]: found local in TCP syn packet from 192.168.0.2
Apr 22 05:16:23 vagrant kernel: [566] tcpriv[info]: found client process info: uid=1000 gid=1000 << Wow!!!!
Apr 22 05:16:23 vagrant kernel: [587] tcpriv[info]: found local out TCP syn packet from 192.168.0.3
```
