.. _mozilla_projects_nss_releases:

Release Notes
=============

.. toctree::
   :maxdepth: 0
   :glob:
   :hidden:

   nss_3_114.rst
   nss_3_113.rst
   nss_3_112.rst
   nss_3_111.rst
   nss_3_110.rst
   nss_3_101_4.rst
   nss_3_109.rst
   nss_3_108.rst
   nss_3_101_3.rst
   nss_3_107.rst
   nss_3_106.rst
   nss_3_105.rst
   nss_3_104.rst
   nss_3_103.rst
   nss_3_102_1.rst
   nss_3_102.rst
   nss_3_101_2.rst
   nss_3_101_1.rst
   nss_3_101.rst
   nss_3_100.rst
   nss_3_99.rst
   nss_3_98.rst
   nss_3_97.rst
   nss_3_96_1.rst
   nss_3_96.rst
   nss_3_95.rst
   nss_3_94.rst
   nss_3_93.rst
   nss_3_92.rst
   nss_3_91.rst
   nss_3_90_4.rst
   nss_3_90_3.rst
   nss_3_90_2.rst
   nss_3_90_1.rst
   nss_3_90.rst
   nss_3_89_1.rst
   nss_3_89.rst
   nss_3_88_1.rst
   nss_3_88.rst
   nss_3_87_1.rst
   nss_3_87.rst
   nss_3_86.rst
   nss_3_85.rst
   nss_3_84.rst
   nss_3_83.rst
   nss_3_82.rst
   nss_3_81.rst
   nss_3_80.rst
   nss_3_79_4.rst
   nss_3_79_3.rst
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

   **NSS 3.114** is the latest version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_3_114_release_notes`

   **NSS 3.101.4 (ESR)** is the latest ESR version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_3_101_4_release_notes`

.. container::

   Changes in 3.114 included in this release:

   - Bug 1977376 - NSS 3.114 source distribution should include NSPR 4.37.
   - Bug 1970079 - Prevent leaks during pkcs12 decoding.
   - Bug 1953731 - Remove redundant assert in p7local.c.
   - Bug 1974515 - Bump nssckbi version to 2.80.
   - Bug 1961848 - Remove expired Baltimore CyberTrust Root.
   - Bug 1972391 - Add TrustAsia Dedicated Roots to NSS.
   - Bug 1974511 - Add SwissSign 2022 Roots to NSS.
   - Bug 1836559 - Add backwards compatibility for CK_PKCS5_PBKD2_PARAMS.
   - Bug 1965328 - Implement PKCS #11 v3.2 trust objects in softoken.
   - Bug 1965328 - Implement PKCS #11 v3.2 trust objects - nss proper.
   - Bug 1974331 - remove dead code in ssl3con.c.
   - Bug 1934867 - DTLS (excl DTLS1.3) Changing Holddown timer logic.
   - Bug 1974299 - Bump nssckbi version to 2.79.
   - Bug 1967826 - remove unneccessary assertion.
   - Bug 1948485 - Update mechanisms for Softoken PCT.
   - Bug 1974299 - convert Chunghwa Telecom ePKI Root removal to a distrust after.
   - Bug 1973925 - Ensure ssl_HaveRecvBufLock and friends respect opt.noLocks.
   - Bug 1973930 - use -O2 for asan build.
   - Bug 1973187 - Fix leaking locks when toggling SSL_NO_LOCKS.
   - Bug 1973105 - remove out-of-function semicolon.
   - Bug 1963009 - Extend pkcs8 fuzz target.
   - Bug 1963008 - Extend pkcs7 fuzz target.
   - Bug 1908763 - Remove unused assignment to pageno.
   - Bug 1908762 - Remove unused assignment to nextChunk.
   - Bug 1973490 - don't run commands as part of shell `local` declarations.
   - Bug 1973490 - fix sanitizer setup.
   - Bug 1973187 - don't silence ssl_gtests output when running with code coverage.
   - Bug 1967411 - Release docs and housekeeping.
   - Bug 1972768 - migrate to new linux tester pool
