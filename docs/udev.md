# Summary

On Linux, by default USB dongles can't be accessed by users, for security reasons. To allow user access, so-called "udev rules" must be installed.

For some users, things will work automatically:

  - Recent Linux distributions (such as Debian 11, Ubuntu Focal, Fedora 32, [Arch Linux](https://wiki.archlinux.org/index.php/Solo)) with systemd 244 or higher automatically detect FIDO devices (check with `systemctl --version`)
  - Fedora seems to use a ["universal" udev rule for FIDO devices](https://github.com/amluto/u2f-hidraw-policy)
  - Our udev rule made it into [libu2f-host](https://github.com/Yubico/libu2f-host/) v1.1.10
  - [Debian Buster](https://packages.ubuntu.com/buster/libu2f-udev) and [Ubuntu Groovy](https://packages.ubuntu.com/groovy/libu2f-udev) can use the `libu2f-udev` package
  - FreeBSD has support in [u2f-devd](https://github.com/solokeys/solo/issues/144#issuecomment-500216020)

If you still need to setup a rule, a simple way to do it is:

```
git clone https://github.com/solokeys/solo.git
cd solo/udev
make setup
```

Or, manually, create a file like [`70-solokeys-access.rules`](https://github.com/solokeys/solo/blob/master/udev/70-solokeys-access.rules) in your `/etc/udev/rules.d` directory.
Additionally, run the following command after you create this file (it is not necessary to do this again in the future):
```
sudo udevadm control --reload-rules && sudo udevadm trigger
```

# How do udev rules work and why are they needed

In Linux, `udev` (part of `systemd`, read `man 7 udev`) handles "hot-pluggable" devices, of which Solo and U2F Zero are examples. In particular, it creates nodes in the `/dev` filesystem (in Linux, everything is a file), which allow accessing the device.

By default, for security reasons often only the `root` user can access these nodes, unless they are whitelisted using a so-called "udev rule". So depending on your system setup, such a udev rule may be necessary to allow non-root users access to the device, for instance yourself when using a browser to perform two-factor authentication.

## What does a udev rule do?
It matches events it receives (typically, comparing with the `==` operator), and performs actions (typically, setting attributes of the node with the `=` or `+=` operators).

## What is `hidraw`?
HID are human-interface devices (keyboards, mice, Solo keys), attached via USB. The `hidraw` system gives software direct ("raw") access to the device.

## Which node is my Solo or U2F Zero security key?
You can either compare `ls /dev` before and after inserting, or use the `udevadm` tool, e.g., by running
```
udevadm monitor --environment --udev | grep DEVNAME
```
Typically, you will detect `/dev/hidraw0`. Using the symlinks above, you can follow symlinks from `/dev/solokey` and `/dev/u2fzero`.

## How do you know if your system is configured correctly?
Try reading and writing to the device node you identified in the previous step. Assuming the node is called `/dev/hidraw0`:

* read: try `cat /dev/solokey`, if you don't get "permission denied", you can access.
* write: try `echo "hello, Solo" > /dev/solokey`. Again, if you don't get denied permission, you're OK.

## Which rule should I use, and how do I do it?
Simplest is probably to copy [Yubico's rule file](https://github.com/Yubico/libu2f-host/blob/master/70-u2f.rules) to `/etc/udev/rules.d/fido.rules` on your system, for instance:
```
$ (cd /etc/udev/rules.d/ && sudo curl https://raw.githubusercontent.com/Yubico/libu2f-host/master/70-u2f.rules -O)
```
This contains rules for Yubico's keys, the U2F Zero, and many others. The relevant line for U2F Zero is:
```
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="8acf", TAG+="uaccess"
```
It matches on the correct vendor/product IDs of 10c4/8acf, and adds the TAG `uaccess`. Older versions of udev use rules such as
```
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="10c4", MODE="0644", GROUP="plugdev"
```
which sets MODE of the device node to readable by anyone.

Now reload the device events.

```
udevadm trigger
```

## What about vendor and product ID for Solo?
| Key | Vendor ID | Product ID |
| --- | --- | --- |
| Solo | 0483 | a2ca |
| U2F Zero | 10c4 | 8acf |

## You got this all wrong, I can't believe it!
Are you suffering from [us being wrong](https://xkcd.com/386/)? Please, send us a [pull request](https://github.com/solokeys/solo/pulls) and prove us wrong :D
