.. _mozilla_projects_nss_runbooks_rootstore:

Updating NSS's Root Store
=========================

.. container::

    The authoritative source for NSS's root store is `certdata.txt <https://hg.mozilla.org/projects/nss/file/tip/lib/ckfw/builtins/certdata.txt>`_.

    certdata.txt contains a list of "certificate blocks" and "trust blocks". A "root" is a certificate (in a certificate block) and its trust bits (in a trust block).
    Blocks are delimited by a blank line. Comments start with a ``#``.
    Certificate blocks include a line that says ``CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE``.
    Trust blocks include a line that says ``CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST``.
    The other lines in a block describe attributes of a PKCS#11 object.

Adding a root
=============

1. Make sure that the NSS ``atob`` and ``addbuiltin`` binaries are in your ``PATH`` and the necessary libraries (``libnsp4``, ``libnssutil3``, etc.) are available.

2. If the certificate is PEM encoded, convert it to DER using the ``atob`` tool::

     atob -i cert.pem -o cert.der

3. Add the certificate to the ``certdata.txt`` file using the ``addbuiltin`` tool::

     addbuiltin -t <trust_bits> -n "<friendly name>" -i <cert.der> >> certdata.txt

   ``<trust_bits>`` is a string of trust bits:

   - ``C,,`` for website trust
   - ``,C,`` for email (SMIME) trust
   - There are a number of more obscure settings; see `CERT_DecodeTrustString <https://searchfox.org/mozilla-central/source/security/nss/lib/certdb/certdb.c#2319>`_ for further details.

This can also be done as a one liner:

     atob -i cert.pem | addbuiltin -t <trust_bits> -n "<friendly name>" >> certdata.txt

Removing a root
---------------

Simply remove both the certificate block and the trust block for the root. Use the nickname and SHA256 fingerprint listed in the bug report to ensure that you are removing the correct blocks. Leave a blank line to delimit adjacent blocks.

Setting a distrust-after date
-----------------------------

Setting a distrust-after date for a root means that any certificates issued by that root after the specified date will no longer be trusted, but certificates issued before that date will still be trusted.

1. Create the timestamp for the desired distrust date. An easy and practical way to do this is using the date command::

     date -d "2019-07-01 00:00:00 UTC" +%s

   The result should be something like: ``1561939200``

2. Then, run ``addbuiltin -d`` to verify the timestamp and do the right conversions. The ``-d`` option takes the timestamp as an argument, which is interpreted as seconds since Unix epoch. The addbuiltin command will show the result in stdout, as it should be inserted in certdata.txt::

     addbuiltin -d 1561939200

   The result should be something like this::

     The timestamp represents this date: Mon Jul 01 00:00:00 2019
     Locate the entry of the desired certificate in certdata.txt
     Erase the CKA_NSS_[SERVER|EMAIL]_DISTRUST_AFTER CK_BBOOL CK_FALSE
     And override with the following respective entry:
     # For Server Distrust After: Mon Jul 01 00:00:00 2019
     CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL
     \061\071\060\067\060\061\060\060\060\060\060\060\132
     END
     # For Email Distrust After: Mon Jul 01 00:00:00 2019
     CKA_NSS_EMAIL_DISTRUST_AFTER MULTILINE_OCTAL
     \061\071\060\067\060\061\060\060\060\060\060\060\132
     END

Incrementing the root store version
-----------------------------------

After making a change to the root store, you must increment the version number in `nssckbi.h <https://searchfox.org/mozilla-central/source/security/nss/lib/ckfw/builtins/nssckbi.h>`_:

1. Bump ``NSS_BUILTINS_LIBRARY_VERSION_MINOR`` to the next even number (odd numbers are used for fixes).
2. Set ``NSS_BUILTINS_LIBRARY_VERSION`` to match.

Checking your work
------------------

1. Check the SHA256 hashes in the output blocks in certdata.txt
2. If the certificate should be trusted for websites, check the ``CKA_TRUST_SERVER_AUTH`` includes ``CKT_NSS_TRUSTED_DELEGATOR``, otherwise it should include ``CKT_NSS_MUST_VERIFY_TRUST``.
3. If the certificate should be trusted for email, check the ``CKA_TRUST_EMAIL_PROTECTION`` line the same way.
4. The ``CKA_TRUST_CODE_SIGNING`` line should always include ``CKT_NSS_MUST_VERIFY_TRUST``.

If making a change to the roots trusted for website authentication, you can confirm your work by rebuilding NSS and running ``vfyserv <hostname>`` which will output either ``PROBLEM WITH CERT CHAIN`` or ``SERVER CONFIGURED CORRECTLY``. All roots trusted for website authentication should have a test site listed in CCADB.

You can also dump certificates from a copy of ``libnssckbi.so``::

    $ mkdir tmp; cd tmp
    $ certutil -N -d .
    $ modutil -add builtins -dbdir . -libfile /path/to/libnssckbi.so
    $ certutil -L -h builtins  # list all certificates in the builtins module
    $ certutil -L -n "<friendly name>" -d .  # pretty print one cert

Root Store Consumers
--------------------

certdata.txt is consumed by various tools to generate root store formats suitable for different libraries and languages.

NSS itself uses a `perl script <https://hg.mozilla.org/projects/nss/file/tip/lib/ckfw/builtins/certdata.perl>`_ to generate a C source file  which builds a PKCS#11 module containing the root store, called libnssckbi.
Firefox used to depend on libnssckbi directly, but now uses its own pure Rust implementation which builds directly from certdata.txt (`build.rs <https://searchfox.org/mozilla-central/source/security/manager/ssl/trust_anchors/build.rs>`_, `output <https://searchfox.org/mozilla-central/source/__GENERATED__/__RUST_BUILD_SCRIPT__/trust-anchors/builtins.rs>`_).

certdata.txt is known to be consumed by several external projects, including: Curl's `mk-ca-bundle <https://curl.se/docs/mk-ca-bundle.html>`_, `Certifi <https://certifi.io/>`_, and the ca-certificates package used by Debian, Ubuntu, Gentoo, Fedora and Arch (`ca-certificates <https://packages.debian.org/stable/ca-certificates>`_).
