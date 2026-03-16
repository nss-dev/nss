.. _mozilla_projects_nss_reference_fc_verifyinit:

FC_VerifyInit
=============

`Name <#name>`__
~~~~~~~~~~~~~~~~

.. container::

   FC_VerifyInit - initialize a verification operation.

`Syntax <#syntax>`__
~~~~~~~~~~~~~~~~~~~~

.. container::

   .. code::

      CK_RV FC_VerifyInit(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      );

`Parameters <#parameters>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. container::

   ``hSession``
      [in] session handle.
   ``pMechanism``
      [in] mechanism to be used for the verification operation.
   ``hKey``
      [in] handle of the key to be used.

`Description <#description>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. container::

   ``FC_VerifyInit`` initializes a verification operation where the signature is an appendix to the
   data.

   A user must log into the token (to assume the NSS User role) before calling ``FC_VerifyInit``.


`Return value <#return_value>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`Examples <#examples>`__
~~~~~~~~~~~~~~~~~~~~~~~~


`See also <#see_also>`__
~~~~~~~~~~~~~~~~~~~~~~~~

.. container::

   -  `NSC_VerifyInit </en-US/NSC_VerifyInit>`__