Unbound
=======
This is a fork of the [official release of Unbound 1.5.4](https://www.unbound.net/downloads/unbound-1.5.4.tar.gz).

## Modifications

* Remove dependencies on farsight/fstrm
* Add a worker thread to the dnstap core for transmitting events
* Use a nice [thread-safe queue library](https://github.com/cgaebel/pipe) to deliver events to the worker thread
* Replace the AF_UNIX socket interface with an AF_INET socket. (Not ideal, but I couldn't get the UNIX socket to open its configured file. Atempts always failed with `ENOENT`, while identical code compiled outside of `unbound` was able to open and write to the same file. ¯\_(ツ)_/¯)

## Building

* Clone (unbound-build)[https://github.com/BlackjackDNS/unbound-build]
* Use bundler to install and run Vagrant:

```
bundle install
ulimit -n 1024; VAGRANT_I_KNOW_WHAT_IM_DOING_PLEASE_BE_QUIET=1 bundle exec vagrant up
ulimit -n 1024; VAGRANT_I_KNOW_WHAT_IM_DOING_PLEASE_BE_QUIET=1 bundle exec vagrant ssh
```

You should now have an Ubuntu 14.04 VM with all necessary tools installed, and the master branch of this repository checked out to `/usr/local/src/unbound`.

* In the build directory on the VM, run:
```
autoreconf -vfi
./configure --enable-dnstap
make -j4
sudo make install
```

## Debugging
The unbound-build cookbook generates a sane `unbound.conf` for debugging. Simply run

```
sudo unbound -d -vvv
```

and profit...

## TODO

* Don't buffer events to memory exhaustion if dnstap can't open it's socket.
* Finish removing libfstrm resources from configuration codelines
