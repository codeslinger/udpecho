DPDK-based UDP echo server
==========================

Building
--------

Only tested on Linux x86_64 with DPDK 2.2.0. Build DPDK via [the instructions found here](http://dpdk.org/doc/quick-start).

Set the `RTE_SDK` env var to the path of your successfully-built DPDK repository. E.g.:

    $ export RTE_SDK=$HOME/dpdk-2.2.0

Then execute:

    $ make

Running
-------

Install a second NIC on your target machine. In EC2, this means adding another ENI to your running instance. Prepare the machine for running a DPDK app via the following (assuming the NIC you want to use is `eth1`):

```
# echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
# [ ! -d /mnt/huge ] && mkdir -p /mnt/huge
# mount -t hugetlbfs nodev /mnt/huge
# ifconfig eth1 down
# modprobe uio
# insmod $RTE_SDK/kmod/igb_uio.ko
# $RTE_SDK/tools/dpdk_nic_bind.py --status
# $RTE_SDK/tools/dpdk_nic_bind.py --bind=igb_uio eth1
# $RTE_SDK/tools/dpdk_nic_bind.py --status
```

Then you can run the server via:

```
$ sudo build/udpecho -c 0x30 -n 1 -- -p 0 -C "(0,0,4),(0,1,5)" -N
```

This will configure the server to use lcores 4 and 5 on a NIC with two RX queues.
