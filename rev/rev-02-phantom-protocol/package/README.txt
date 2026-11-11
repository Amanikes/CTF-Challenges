Aegis Communications — Phantom Protocol analyst package
=======================================================

Case PHTM-0417
--------------

  Phantom Protocol was a short-lived access control pilot operated by Aegis
  Communications. The service was decommissioned before its documentation was
  published and the engineer responsible has left the company.

  This package was recovered from a field intercept. It contains the client
  application and the protocol data file it uses. No source code, build scripts
  or operator documentation were recovered.

Contents
--------

  phantom-client   Linux x86_64 executable
  protocol.dat     Protocol data consumed by the client
  README.txt       This file

Requirements
------------

  * Linux x86_64 (ELF64)
  * No additional libraries or network access

Extracting the package
----------------------

  unzip phantom-protocol-package.zip
  cd phantom-protocol
  chmod +x phantom-client

Running the client
------------------

  ./phantom-client

  With no arguments the client prints a usage summary.

Testing a candidate token
-------------------------

  ./phantom-client --verify 'CANDIDATE-TOKEN'

  The client compares a candidate against the recovered protocol data and
  reports one of:

    ACCESS GRANTED    the candidate is the accepted token
    ACCESS DENIED     the candidate is not accepted

  It never prints the stored token.

Important
---------

  protocol.dat must stay in the same directory as phantom-client. The client
  locates it relative to its own path, so the two files travel together.

  Treat the executable and protocol.dat as a single artifact: the client alone
  cannot validate anything, and the data file alone carries no readable token.

Analysis notes
--------------

  1. Inspect the executable's file format, metadata and strings before running
     anything. Start with the tools you would use on any unknown binary.

  2. Locate the routine that processes candidate tokens and follow how each
     candidate byte is handled. The client only reports a final decision, so the
     comparison itself is where the information lives.

  3. Expect repeated byte operations, position-dependent arithmetic and bit
     rotations. Every stage applied by the client is reversible: whatever the
     client does to a candidate, it must be possible to undo on the stored data.

  The protocol data file has its own small structure. Its header tells you how
  much payload follows, and the payload is exactly as long as the accepted
  token.

  Do not attempt to brute force the token; the transformation is fully
  recoverable from the supplied artifacts.

Distribution
------------

  Internal use only. Do not redistribute outside the case team.
