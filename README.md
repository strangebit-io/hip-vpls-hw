# Host Identity Protocol Based VPLS tailored for NanoPiR2S

Deployment scenario:

```
+---------+ 100Mb/s  +-----------+ 100Mb/s+----------------+
| IP cam  |----------| CE Switch |--------| Ambient sensors|
+---------+          +-----------+        +----------------+
                            |
                            | 1 Gb/s
                            |
                     +-----------+
                     |HIP switch | NanoPi R2S
                     +-----------+
                            |                                                 +------------------+
                            | 1 Gb/s                                          | Sensors/Actuators|
  NanoPi R2S                |               NanoPi R2S                       /+------------------+
+-----------+  1Gb/s +--------------+1 Gb/s+-----------+ 1 Gb/s+-----------+/ 100 Mb/s
|HIP switch |--------| Public cloud |------|HIP switch |-------| CE Switch |
+-----------+        +--------------+      +-----------+       +-----------+
                            |  |                                            \ 100 Mb/s
                            |  +--------+                                    \
                            | 1 Gb/s    |                                     +------------------+
                       +-----------+    |                                     | Sensors/Actuators|
            NanoPi R2S |HIP switch |    |                                     +------------------+
                       +-----------+    |
                            | 1 Gb/s    |
+-----------+ 1 Gb/s   +-----------+    | 10 Mb/s
|  Server   |----------|CE switch  |    |
+-----------+     +----+-----------+    |
                  |          | 1 Gb/s   |
+-----------+-----+          |          |
| DHCP/DNS  | 1 Gb/s   +-----------+    |
+-----------+          |   Router  |----+
                       +-----------+
                       
```
To deploy HIP-VPLS on hardware (HIP switch) follow these steps:

In folder hip-vpls-hw perform the following (generate keys, edit the files):
- generate the public and private keys for all routers
- generate HIT using appropriate tool (can be found under tools folder)
- update the hosts file (add mapping between HIT and IP address)
- update the mesh file (add all pairs of HITs)
- update the rules file (update the firewall rules)
- in config.py you need to select proper options (change the CE facing interface, public source IP address, change algorithms)


First make sure that the SHA2 and AES libraries are compiled for the nanoPI R2S. And then follow the instructions below. But better run it on Intel CPU with NI instructions. 

The SHA2 library for the Intel CPU:

https://github.com/dmitriykuptsov/hw-crypto-sha2-ni

The AES library for the Intel CPU:

https://github.com/dmitriykuptsov/hw-crypto-aes-ni

Copy the compiled libraries to symmetric crypto folder and then deploy the system.

Next deploy the service:

```
$ git clone git@github.com:strangebit-io/hip-vpls-hw.git
$ cd hip-vpls-hw
$ cd deploy
$ sudo bash deploy.sh
```

Finally run the service:
```
$ sudo service hip-vpls start
```

Repeat the same procedure on all HIP switches.

# Stress test scenarios

We have tested the testbed in the following way:
- end-to-end iperf test
- multicast traffic (RTSP stream to a multicast source)

Currently the performance is not production grade. We have got 40Mb/s in a simulation environment.

# Compiling the source code for performance

We are currently working on performance of the solution.


# Hardware accelerated AES256 encryption

We have implemented hardware accelerated AES256 for the Nano PI R2S and have got x10 improvement in throughput.


