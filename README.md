# tcpriv

#### A Design of Access Control Architecture Separating Privilege Transparently via TCP Connection Based on Process Information

`tcpriv` separates privilege on TCP using Linux owner information of `task_struct`. `tcpriv` is a kernel module for Linux. We develop `tcpriv` on Ubuntu 20.04 and Linux kernel 5.4. Please see `Vagrantfile` and `misc/provision.sh`.

Now under depelopment.

## Quick setup

- install vagrant

- setup, build and test enviroment

```
# Support mutliple vm building
vagrant up server # waiting client access after provisioning
vagrant up client # connecting server for testing

# on one terminal
vagrant ssh client

# on another terminal
vagrant ssh server
```

all setup phase was provisioned automatically by `misc/provision.sh` such as installing packages, setup kernel module enviroment, building kernel module and insmod/rmmod tcpriv as a kernel module.

- test using vagrant provision

```
$ vagrant provision server
...
server: TEST: server is waiting for client..
server: waiting...
server: connected: 192.168.0.2
server: syn_len: 60
server: found tcpriv's information: kind=254 length=10 ExID=0xf991 uid=1000 
server: tcpriv: all test success.
```

```
$ vagrant provision client
...
client: TEST: client is trying to connect server...
client: [tcpriv] connect to 192.168.0.3
client: client test done
```

## Experiment

#### Remote servers get process information like uid/gid from a client server process transparently

<p align="center">
  <img alt="tcpriv flow" src="https://github.com/matsumotory/tcpriv/blob/master/misc/figures/tcpriv-flow.png?raw=true" width="800">
</p>

#### 1. A server (192.168.0.3)

```
# in host
vagrant up server # or vagrant provision server
vagrant ssh server
cd ~/tcpriv/test
./server
```

#### 2. A server (192.168.0,2)

```
# in host
vagrant up client # or vagrant provision client
vagrant ssh client

# in vm
cat /proc/net/tcpriv 
# tcpriv v0.0.1 was enabled.

# check uid/gid
id
# uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lxd),118(lpadmin),119(sambashare)

# access tcp port
nc -vz 192.168.0.3 55226
# Connection to 192.168.0.3 55226 port [tcp/ssh] succeeded!

# change uid
id sshd
# uid=111(sshd) gid=65534(nogroup) groups=65534(nogroup)

sudo -u sshd nc -vz 192.168.0.3 55226
# Connection to 192.168.0.3 55226 port [tcp/ssh] succeeded!
```

#### 3. The remote server (192.168.0.3)

```
vagrant@server:~/tcpriv/test$ ./server
tcpriv[info]: waiting...
tcpriv[info]: connected: 192.168.0.2
tcpriv[info]: syn_len: 60
tcpriv[info]: found tcpriv's information: kind=254 length=10 ExID=0xf991 uid=1000
tcpriv[info]: all test success.
```

```
vagrant@server:~/tcpriv/test$ ./server
tcpriv[info]: waiting...
tcpriv[info]: connected: 192.168.0.2
tcpriv[info]: syn_len: 60
tcpriv[info]: found tcpriv's information: kind=254 length=10 ExID=0xf991 uid=111
server: server.c:146: read_saved_syn: Assertion `tcpriv_uid == 1000' failed.
Aborted (core dumped)
```

