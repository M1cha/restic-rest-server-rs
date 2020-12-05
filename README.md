# Restic Rest Server (rust)
I had problems using the [original rest-server](https://github.com/restic/rest-server)
with yocto on aarch64. Apparently golang applications are not being compiled
proberly and have random undefined behavior.

Since the protocol is very simple and properly specified, I wrote my own instead
of investing time in debugging that problem - especially since golang doesn't
seem to be well supported in yocto anyway.
