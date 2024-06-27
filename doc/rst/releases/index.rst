.. _mozilla_projects_nss_releases:

Releases
========

.. toctree::
   :maxdepth: 0
   :glob:
   :hidden:

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
   nss_3_91_0.rst
   nss_3_90_3.rst
   nss_3_90_2.rst
   nss_3_90_1.rst
   nss_3_90_0.rst
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

   **NSS 3.101** is the latest version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_3_101_release_notes`

   **NSS 3.90.2 (ESR)** is the latest version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_3_90_2_release_notes`

.. container::

   Changes in 3.101 included in this release:

   - Bug 1900413 - add diagnostic assertions for SFTKObject refcount. 
   - Bug 1899759 - freeing the slot in DeleteCertAndKey if authentication failed
   - Bug 1899883 - fix formatting issues. 
   - Bug 1889671 - Add Firmaprofesional CA Root-A Web to NSS.
   - Bug 1899593 - remove invalid acvp fuzz test vectors. 
   - Bug 1898830 - pad short P-384 and P-521 signatures gtests.
   - Bug 1898627 - remove unused FreeBL ECC code. r=rrelyea
   - Bug 1898830 - pad short P-384 and P-521 signatures. 
   - Bug 1898825 - be less strict about ECDSA private key length. 
   - Bug 1854439 - Integrate HACL* P-521. 
   - Bug 1854438 - Integrate HACL* P-384. 
   - Bug 1898074 - memory leak in create_objects_from_handles. 
   - Bug 1898858 - ensure all input is consumed in a few places in mozilla::pkix 
   - Bug 1884444 - SMIME/CMS and PKCS #12 do not integrate with modern NSS policy 
   - Bug 1748105 - clean up escape handling 
   - Bug 1896353 - Use lib::pkix as default validator instead of the old-one 
   - Bug 1827444 - Need to add high level support for PQ signing.
   - Bug 1548723 - Certificate Compression: changing the allocation/freeing of buffer + Improving the documentation 
   - Bug 1884444 - SMIME/CMS and PKCS #12 do not integrate with modern NSS policy
   - Bug 1893404 - Allow for non-full length ecdsa signature when using softoken
   - Bug 1830415 - Modification of .taskcluster.yml due to mozlint indent defects
   - Bug 1793811 - Implement support for PBMAC1 in PKCS#12 
   - Bug 1897487 - disable VLA warnings for fuzz builds.
   - Bug 1895032 - remove redundant AllocItem implementation. 
   - Bug 1893334 - add PK11_ReadDistrustAfterAttribute. 
   - Bug 215997  - Clang-formatting of SEC_GetMgfTypeByOidTag update
   - Bug 1895012 - Set SEC_ERROR_LIBRARY_FAILURE on self-test failure
   - Bug 1894572 - sftk_getParameters(): Fix fallback to default variable after error with configfile. 
   - Bug 1830415 - Switch to the mozillareleases/image_builder image
