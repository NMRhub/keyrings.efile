# keyrings.efile

We needed a keyrings implementation that just worked in headless environments. 
**keyrings.efile** encrypts passwords using files stored on the local filesystem (*/var/tmp/*).

It's not secure if an attacker can read all the files, but at least doesn't store the password
as plain text.

The current implemetation has the kerying priority set to 20 to take precedence over the Chainer backend. 
This may change in future releaeses.

## Update
Version 2.0 implements *delete_password*.

Version 3.0 adds *FallbackPasswordHandler* and logging.
