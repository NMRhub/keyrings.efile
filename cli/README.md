# keyrings.efile.cli

Command line tool to manage passwords stored by [keyrings.efile](https://github.com/NMRhub/keyrings.efile).

    pip install keyrings.efile.cli

or

    pip install keyrings.efile[cli]

## Usage

    keyrings-efile list                  # list stored services and users
    keyrings-efile show SERVICE USER     # display password
    keyrings-efile delete SERVICE USER   # delete entry
    keyrings-efile -l DEBUG list         # enable debug logging
