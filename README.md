# keyrings.efile

We needed a keyrings implementation that just worked in headless environments. 
**keyrings.efile** encrypts passwords using files stored on the local filesystem (*/var/tmp/*).

It's not secure if an attacker can read all the files, but at least doesn't store the password
as plain text.

The current implemetation has the kerying priority set to 20 to take precedence over the Chainer backend. 
This may change in future releaeses.

## Usage
Once installed, the backend is picked up by the standard *keyring* API:

```python
import keyring

keyring.set_password('mydatabase', 'alice', 'secret')
print(keyring.get_password('mydatabase', 'alice'))   # secret
keyring.delete_password('mydatabase', 'alice')
```

The backend can also be used directly, regardless of which keyring is active:

```python
from keyrings.efile import EncryptedFile

ef = EncryptedFile()
ef.set_password('mydatabase', 'alice', 'secret')
print(ef.get_password('mydatabase', 'alice'))        # secret
print(ef.list_entries())                             # [('mydatabase', 'alice')]
ef.delete_password('mydatabase', 'alice')
```

*FallbackPasswordHandler* returns the stored password, or prompts for one if none is stored.
A prompted password is saved only if the *with* block completes without an exception,
so a mistyped password is not remembered:

```python
from keyrings.efile import FallbackPasswordHandler

handler = FallbackPasswordHandler('mydatabase', 'alice')
with handler as password:
    connection = connect(user='alice', password=password)  # raises on bad password
```

Call `handler.delete_password()` to remove a stored password that is no longer valid.

Debug logging is available through the *keyrings.efile* logger:

```python
import logging
logging.basicConfig()
logging.getLogger('keyrings.efile').setLevel(logging.DEBUG)
```

## Update
Version 2.0 implements *delete_password*.

Version 3.0 adds *FallbackPasswordHandler* and logging.

Version 4.0 adds *list_entries*.

## Command line
The *keyrings-efile* command is provided by the separate
[keyrings.efile.cli](cli/README.md) package, installed with either
`pip install keyrings.efile.cli` or `pip install keyrings.efile[cli]`:

    keyrings-efile list                  # list stored services and users
    keyrings-efile show SERVICE USER     # display password
    keyrings-efile delete SERVICE USER   # delete entry
