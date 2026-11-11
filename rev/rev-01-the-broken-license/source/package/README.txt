Northstar License Manager 2.4.1
===============================

Recovered release package
-------------------------

  northstar-license   Linux x86_64 executable
  license.dat         License data used by the executable
  README.txt          This file

Requirements
------------

  * Linux x86_64 (ELF64)
  * No additional libraries or services

Extracting the package
----------------------

  unzip northstar-license-package.zip
  cd northstar-license-package
  chmod +x northstar-license

Running the utility
-------------------

  ./northstar-license

  The utility prints its version banner and asks for a license key on standard
  input. Press Enter after typing the key.

  Example session shape:

    $ ./northstar-license
    Northstar License Manager 2.4.1
    Licensed to: Northstar Systems (legacy entitlement)
    Enter license key: <type a key here>
    License accepted. Northstar License Manager is now registered.

Important
---------

  license.dat must remain in the same directory as the executable. The utility
  looks for it next to itself at start-up and reports a missing data file if it
  cannot be found. Copy both files together.

  The file is not a configuration file. Editing it changes the outcome of the
  validation and is not supported.

Support
-------

  The original developer and the license documentation are no longer available.
  This archive is provided for internal review only; it must not be
  redistributed outside Northstar Systems.
