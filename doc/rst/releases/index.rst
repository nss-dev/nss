.. _mozilla_projects_nss_releases:

Releases
========

.. toctree::
   :maxdepth: 0
   :glob:
   :hidden:

   nss_3_88.rst
   nss_3_87.rst
   nss_3_86.rst
   nss_3_85.rst
   nss_3_84.rst
   nss_3_83.rst
   nss_3_82.rst
   nss_3_81.rst
   nss_3_80.rst
   nss_3_79_2.rst
   nss_3_79_1.rst
   nss_3_79.rst
   nss_3_78_1.rst
   nss_3_78.rst
   nss_3_77.rst
   nss_3_76_1.rst
   nss_3_76.rst
   nss_3_75.rst
   nss_3_74.rst
   nss_3_73_1.rst
   nss_3_73.rst
   nss_3_72_1.rst
   nss_3_72.rst
   nss_3_71.rst
   nss_3_70.rst
   nss_3_69_1.rst
   nss_3_69.rst
   nss_3_68_4.rst
   nss_3_68_3.rst
   nss_3_68_2.rst
   nss_3_68_1.rst
   nss_3_68.rst
   nss_3_67.rst
   nss_3_66.rst
   nss_3_65.rst
   nss_3_64.rst

.. note::

   **NSS 3.88** is the latest version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_3_88_release_notes`

   **NSS 3.79.2** is the latest ESR version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_3_79_2_release_notes`


.. container::

   Changes in 3.88 included in this release:

   - Bug 1212915 - Add check for ClientHello SID max length. This is tested by Bogo tests 
   - Bug 1771100 - Added EarlyData ALPN test support to BoGo shim. 
   - Bug 1790357: ECH client - Discard resumption TLS < 1.3 Session(IDs|Tickets) if ECH configs are setup.
   - Bug 1714245 - On HRR skip PSK incompatible with negotiated ciphersuites hash algorithm. 
   - Bug 1789410 - ECH client: Send ech_required alert on server negotiating TLS 1.2. Fixed misleading Gtest, enabled corresponding BoGo test.
   - Bug 1771100 - Added Bogo ECH rejection test support.
   - Bug 1771100 - Added ECH 0Rtt support to BoGo shim. 
   - Bug 1747957 - RSA OAEP Wycheproof JSON
   - Bug 1747957 - RSA decrypt Wycheproof JSON
   - Bug 1747957 - ECDSA Wycheproof JSON
   - Bug 1747957 - ECDH Wycheproof JSON
   - Bug 1747957 - PKCS#1v1.5 wycheproof json
   - Bug 1747957 - Use X25519 wycheproof json
   - Bug 1766767 - Move scripts to python3
   - Bug 1809627 - Properly link FuzzingEngine for oss-fuzz.
   - Bug 1805907 - Extending RSA-PSS bltest test coverage (Adding SHA-256 and SHA-384) 
   - Bug 1804091 NSS needs to move off of DSA for integrity checks
   - Bug 1805815 - Add initial testing with ACVP vector sets using acvp-rust
   - Bug 1806369 - Don't clone libFuzzer, rely on clang instead