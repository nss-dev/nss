.. _mozilla_projects_nss_releases:

Release Notes
=============

.. toctree::
   :maxdepth: 0
   :glob:
   :hidden:

   nss_3_116.rst
   nss_3_115_1.rst
   nss_3_115.rst
   nss_3_114_1.rst
   nss_3_114.rst
   nss_3_113.rst
   nss_3_112_1.rst
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

   **NSS 3.116** is the latest version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_3_116_release_notes`

   **NSS 3.112.1 (ESR)** is the latest ESR version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_3_112_1_release_notes`

.. container::

   Changes in 3.116 included in this release:

   - Bug 1983308 - disable DSA in NSS script tests.
   - Bug 1983308 - Disabling of some algorithms: generic cert.sh.
   - Bug 1981046 - Need to update to new mechanisms.
   - Bug 1983320 - Add ML-DSA public key printing support in NSS command-line utilities.
   - Bug 1986802 - note embedded scts before revocation checks are performed.
   - Bug 1983320 - Add support for ML-DSA keys and mechanisms in PKCS#11 interface.
   - Bug 1983320 - Add support for ML-DSA key type and public key structure.
   - Bug 1983320 - Enable ML-DSA integration via OIDs support and SECMOD flag.
   - Bug 1983308 - disable kyber.
   - Bug 1965329 - Implement PKCS #11 v3.2 PQ functions (use verify signature).
   - Bug 1983308 - Disable dsa - gtests.
   - Bug 1983313 - make group and scheme support in test tools generic.
   - Bug 1983770 - Create GH workflow to automatically close PRs.
   - Bug 1983308 - Disable dsa - base code.
   - Bug 1983308 - Disabling of some algorithms: remove dsa from pk11_mode.
   - Bug 1983308 - Disable seed and RC2 bug fixes.
   - Bug 1982742 - restore support for finding certificates by decoded serial number.
   - Bug 1984165 - avoid CKR_BUFFER_TO_SMALL error in trust lookups.
   - Bug 1983399 - lib/softtoken/{sdb.c,sftkdbti.h}: Align sftkdb_known_attributes_size type.
   - Bug 1965329 - Use PKCS #11 v3.2 KEM mechanisms and functions.
