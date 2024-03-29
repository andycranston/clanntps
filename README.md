# clanntps - Closed LAN NTP Server in Python

A very simple Network Time Procotol server implementation
in Python 3 for situations where access to any other NTP servers
is not possible.

# Quick Start

For Linux only.

Run as follows:

```
sudo python3 clanntps.pt --bind 1.2.3.4
```

Where `1.2.3.4` is the IPv4 address of the network interface adapter you
want to listen for NTP request packets.

# Warnings

This NTP server does not refer to any other time source. The time offered to clients
is based on the system host clock. This time can be wrong, can drift and can change in
big steps without warning.

The `clanntps.py` program is for test/demo environments ONLY!

For production make sure you have a network path to an official NTP time source.

# Time skew feature

It is possible to skew the time for one of more clients by creating a file called:

```
/usr/local/etc/clanntps.skew
```

To have the time for the client with IP address 192.168.1.71 run 5 minutes behind add the following line
to the `/usr/local/etc/clanntps.skew` file:

```
skew 192.168.1.71 -300
```

Stop and restart the `clanntps.py` program.

Each time a NTP request comes in from `192.168.1.71` 300 seconds will be subtracted from the actual time and
that `skewed` time will be returned to the NTP client.

To skew time forward use a positive integer.

If you want to use a different file to `/usr/local/etc/clanntps.skew` then use the `--skew` command line option as follows:

```
sudo python3 clanntps.pt --bind 1.2.3.4 --skew myfile.skew
```

# Exampe systemd service file

This repo contains a file called:

```
clanntps.service
```

which is an example systemd service file for Linux systems using systemd.

Edit the file and change the IP address.

Then run commands similar to:

```
sudo cp clanntps.service /etc/systemd/system/clanntps.service
cd /etc/systemd/system
sudo chown root:root clanntps.service
sudo chmow u=rw,go=r clanntps.service
sudo systemctl daemon-reload
sudo systemctl enable clanntps.service
sudo systemctl start clanntps.service
```

The `clanntps.py` program logs message to syslog. Check the system to verify the program started successfully.


--------------------------------------

End of file
