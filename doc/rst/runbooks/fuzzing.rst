.. _mozilla_projects_nss_runbooks_fuzzing:

Fuzzing NSS
===========

NSS uses `libFuzzer <https://llvm.org/docs/LibFuzzer.html>`_ to fuzz-test its
parsing and protocol code.  The fuzz targets live under ``fuzz/targets/`` and
cover ASN.1/DER decoding, certificate-DN parsing, TLS/DTLS client and server
handshakes, PKCS #7/#8/#12, S/MIME, and ECH configuration decoding.

Every target is compiled into its own binary (e.g. ``nssfuzz-tls-client``) and
run with AddressSanitizer and UndefinedBehaviorSanitizer enabled by default.

Building the fuzz targets
-------------------------

The fuzz build requires **clang**.

.. code-block:: bash

   # Build all fuzz targets (with ASan + UBSan + libFuzzer).
   ./build.sh --fuzz

   # Optionally skip the test suite to speed up the build.
   ./build.sh --fuzz --disable-tests

The build system also accepts two specialised fuzz modes:

``--fuzz=oss``
   Used by OSS-Fuzz.  Skips ASan/UBSan (the OSS-Fuzz build infrastructure
   supplies its own sanitizer flags) and adds ``-Dfuzz_oss=1``.

``--fuzz=tls``
   Enables *Totally Lacking Security* mode (see `below <Totally Lacking Security
   (TLS) mode_>`_).

After a successful build the fuzz binaries are placed in
``../dist/Debug/bin/``.  Each binary is named ``nssfuzz-<target>``, for
example ``nssfuzz-tls-client`` or ``nssfuzz-asn1``.

The exact compiler and sanitizer flags are configured in ``coreconf/fuzz.sh``.

Totally Lacking Security (TLS) mode
-----------------------------------

``--fuzz=tls`` builds NSS in the special 'Totally Lacking Security' mode that mocks out various cryptographic checks. This mode was originally designed for the running the TLS-specific fuzz targets, hence the name, but it's been extended to handle other fuzzers where cryptographic checks get in the way of fuzzing (e.g. PKCS #7).

Fuzzers can be registered to use this mode by adding a file named ``<target>-no_fuzzer_mode.options`` in the ``fuzz/options/`` directory.

Running a fuzz target locally
-----------------------------

The fuzz targets use the standard `libFuzzer interface <https://llvm.org/docs/LibFuzzer.html>`_.

.. code-block:: bash

   # Run with an existing corpus directory.
   ../dist/Debug/bin/nssfuzz-tls-client fuzz/corpus/tls-client/

   # Useful libFuzzer flags:
   #   -max_total_time=300   Stop after 300 seconds.
   #   -fork=30 Run 30 parallel instances
   #   -runs=0               Just verify the corpus (no new mutations).

To reproduce a crash from a test case file:

.. code-block:: bash

   ../dist/Debug/bin/nssfuzz-tls-client path/to/crash-input


Corpus management
-----------------

Using a good corpus is essential for effective fuzzing.  A corpus is a set of test inputs that the fuzzer uses as a starting point.  A good corpus should be diverse and cover a wide range of code paths.

Downloading the public OSS-Fuzz corpus
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

OSS-Fuzz publishes public corpora for every target.  You can download them
directly:

.. code-block:: bash

   target=tls-client
   mkdir -p fuzz/corpus/$target && cd fuzz/corpus/$target
   curl -O "https://storage.googleapis.com/nss-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/nss_${target}/public.zip"
   unzip public.zip && rm public.zip
   cd -

Replace ``tls-client`` with the name of the target you want.

Extracting corpus from existing tests (Frida)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

NSS ships a `Frida <https://frida.re/>`_-based tool that intercepts NSS API
calls during test execution and saves the inputs as corpus files.  This is a
great way to bootstrap a corpus from the existing test suite.

The tooling lives in ``fuzz/config/frida_corpus/``:

* ``hooks.js`` -- Frida script that attaches interceptors to NSS functions
  (e.g. ``SEC_ASN1DecodeItem_Util``, ``ssl_DefRecv``, etc.) and sends the
  captured data back to the Python harness.
* ``cli.py`` -- Python harness that spawns a program under Frida, receives
  intercepted data, and writes corpus files to disk.

Continuous fuzzing (OSS-Fuzz)
-----------------------------

All NSS fuzz targets run continuously on `OSS-Fuzz <https://oss-fuzz.com/>`_.
The project configuration lives at
`google/oss-fuzz: projects/nss/project.yaml <https://github.com/google/oss-fuzz/blob/master/projects/nss/project.yaml>`_.

Useful dashboards:

* `OSS-Fuzz introspector for NSS <https://introspector.oss-fuzz.com/project-profile?project=nss>`_
  -- code coverage and fuzz introspector reports.
* `ClusterFuzz dashboard <https://oss-fuzz.com/>`_ -- requires access; shows
  crash reports, corpus statistics, and coverage.

Fuzzing on Taskcluster (CI)
---------------------------

NSS fuzzing tasks run on Taskcluster as part of the CI pipeline.  The entry
point is ``automation/taskcluster/scripts/fuzz.sh`` and the jobs are registered in
``taskcluster/kinds/fuzz/kind.yml``, which:

1. Fetches the pre-built fuzz binaries.
2. Downloads the public OSS-Fuzz corpus for the target.
3. Reads libFuzzer options from ``fuzz/options/<target>.options``.
4. Runs ``nssfuzz-<target>`` against the corpus.

You can trigger fuzzing tasks on try by pushing to the NSS try repository.
Results are visible on `Treeherder <https://treeherder.mozilla.org/jobs?repo=nss-try>`_.

Mozilla internal services
^^^^^^^^^^^^^^^^^^^^^^^^^

Two services maintained in `MozillaSecurity/orion <https://github.com/MozillaSecurity/orion>`_
support NSS fuzzing:

* `nss-coverage <https://github.com/MozillaSecurity/orion/tree/master/services/nss-coverage>`_
  -- collects code coverage information from fuzzing runs.  Reports are
  published at https://fuzzmanager.fuzzing.mozilla.org/covmanager/reports/.
* `nss-corpus-update <https://github.com/MozillaSecurity/orion/tree/master/services/nss-corpus-update>`_
  -- mirrors the public OSS-Fuzz corpora and populates the private corpus
  bucket with new test cases.

Adding a new fuzz target
------------------------

Fuzz target source files go in ``fuzz/targets/``.  When adding a new target,
keep the following in mind:

1. **Create an ``.options`` file** at ``fuzz/options/<target>.options``.  Other
   tooling (CI, OSS-Fuzz) depends on its existence.  At minimum it should
   set ``max_len`` and ``len_control``:

   .. code-block:: ini

      [libfuzzer]
      len_control = 100
      max_len = 16777215

2. **Register the target** in ``fuzz/targets/targets.gyp`` and
   ``fuzz/fuzz.gyp`` so the build system picks it up.

3. **Schedule CI runs** by adding the corresponding fuzzing tasks in the
   Taskcluster task graph configuration at
   ``taskcluster/kinds/fuzz/kind.yml``.

4. **(Optional but recommended) Add suitable Frida hooks** in ``fuzz/config/frida_corpus/hooks.js``
   and ``fuzz/config/frida_corpus/cli.py`` to automatically extract corpus
   inputs from existing tests.