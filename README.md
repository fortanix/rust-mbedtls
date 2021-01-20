# mbedtls

[![Build Status](https://travis-ci.com/fortanix/rust-mbedtls.svg?branch=master)](https://travis-ci.com/fortanix/rust-mbedtls)

This is an idiomatic Rust wrapper for MbedTLS, allowing you to use MbedTLS with
only safe code while being able to use such great Rust features like error
handling and closures.

Additionally, building on MbedTLS's focus on embedded use, this crate can be
used in a no_std environment.

## Building

This crate depends on the mbedtls-sys-auto crate, see below for build details.

### Features

This is a list of the Cargo features available for mbedtls. Features in
**bold** are enabled by default.

* **aesni** Enable support for the AES-NI instructions. On SGX, this feature is
            enabled automatically.
* *debug* Enable debug printing to stdout. You need to configure the debug
          threshold at runtime.
* *dsa* Enable support for DSA signatures
* *force_aesni_support* MbedTLS normally uses runtime detection of AES-NI
                        support. With this feature, always use AES-NI. This
                        will result in undefined instruction exceptions on
                        unsupported processors. On SGX, this feature is
                        enabled automatically.
* *mpi_force_c_code* Enables the `mpi_force_c_code` feature in mbedtls-sys
* *legacy_protocols* Enable support for SSLv3, TLSv1.0 and TLSv1.1
* *no_std_deps* On no_std, you must enable this feature. It enables optional
                dependencies needed on no_std. If the `std` feature is enabled,
                this feature is ignored.
* **padlock** Enable support for VIA padlock.
* *pkcs12* Enable code to parse PKCS12 files using yasna
* *pkcs12_rc2* Enable use of RC2 crate to decrypt RC2-encrypted PKCS12 files
* *rdrand* Enable the RDRAND random number generator. On SGX, this feature is
           enabled automatically.
* **std** If this feature is not enabled, this crate is a no_std crate. (An
          allocator is *required*) The necessary C functions to make MbedTLS
          work without libc will be provided.
* **time** Enable time support in mbedtls-sys.
* *zlib* Enable zlib support in mbedtls-sys.

PRs adding new features are encouraged.

# mbedtls-sys-auto

Unfortunately, the `mbedtls-sys` crate on crates.io is claimed by another,
apparently inactive, project.

To use this crate, you will need to have **clang** and **cmake** installed, see
below for details.

## Configuring and linking MbedTLS

MbedTLS has a plethora of compile-time configuration options that significantly
impact what functionality is available. To make sure Rust's view of MbedTLS
matches up with what's built in C, MbedTLS must be configured using Cargo
features (see next section) and built using mbedtls-sys's build script.

The mbedtls-sys crate includes the MbedTLS source code, the MbedTLS version
will have the same major.minor version as the crate. Instead of using the
provided source, you can specify the path to your own source tree using the
`RUST_MBEDTLS_SYS_SOURCE` environment variable. It is not recommended to use a
custom source that is based on a different version of MbedTLS than the one
provided in the crate.

The build script will perform the following steps:
1. generate an appropriate config.h (any existing config.h is ignored),
2. compile a statically-linked MbedTLS, this requires cmake to be installed,
3. generate Rust bindings based on the configuration, this requires clang to be
   installed.

### Features

This is a list of the Cargo features available for mbedtls-sys. Features in
**bold** are enabled by default.

* **aesni** Enable support for the AES-NI instructions. On SGX, this feature is
            enabled automatically.
* *aes_alt* Allow an alternative implementation of AES, replacing the
  T-tables code.
* *custom_has_support* Override runtime feature detection. In a dependent
                       crate, you must define the functions
                       `mbedtls_aesni_has_support` and
                       `mbedtls_padlock_has_support` following the MbedTLS
                       function signatures. On SGX, this feature is enabled
                       automatically.
* *custom_printf* Provide a custom printf implementation. printf is only used
                  for the self tests. In a dependent crate, you must define the
                  `mbedtls_printf` function with the standard printf signature.
* **debug** Enable debug callbacks.
* *havege* Enable the Hardware Volatile Entropy Gathering and Expansion
           (HAVEGE) algorithm.
* **legacy_protocols** Enable support for SSLv3, TLSv1.0 and TLSv1.1
* *mpi_force_c_code* MbedTLS uses assembly code for MPI functions, when available.
                     In some situations we may prefer C code instead. This is in
                     particular the case on x86 platforms where compile-time mitigation
                     for speculative execution is required (e.g., LVI). Letting the
                     compiler insert the required lfences during C-code compilation may
                     result in faster code than letting the compiler apply mitigations
                     on assembly code.
* **padlock** Enable support for VIA padlock.
* *pkcs11* Enable PKCS#11 support. This requires pkcs11-helper to be installed.
* **std** If this feature is not enabled, this crate is a no_std crate. In a
          no_std configuration without libc, you need to provide your own
          versions of the following standard C functions: `calloc()`/`free()`,
          and `strstr()`/`strlen()`/`strncpy()`/`strncmp()`/`strcmp()`/
          `snprintf()`, and `memmove()`/`memcpy()`/`memcmp()`/`memset()`, and
          `rand()`/`printf()`. For `printf()`, you can optionally use the
          `custom_printf` feature. `rand()` is only needed for the selftests.
          On UNIX platforms, this also enables networking, filesystems and OS
          entropy.
* **threading** Enable threading support. On `cfg(unix)` platforms, this uses
                pthreads. On other platforms, you need to provide a custom
                threading implementation. In a dependent crate, you must define
                the functions `mbedtls_mutex_init()`, `mbedtls_mutex_free()`,
                `mbedtls_mutex_lock()`, and `mbedtls_mutex_unlock()` following
                the  MbedTLS function signatures.
* **time** Enable time support. On `cfg(unix)` platforms, this uses `libc`. On
           other platforms, you need to provide your own implementations of
           `mbedtls_platform_gmtime_r(const long long*, struct tm*)` and
           `mbedtls_time(long long*)`.
* *trusted_cert_callback* Enable trusted certificate callback support.
* **zlib** Enable zlib support.

For the complete mapping of features to config.h defines, see
[mbedtls-sys/build/config.rs]. PRs adding new features are encouraged.

## MbedTLS version updates

Instructions for updating to new MbedTLS source code releases in `mbedtls-sys/`:

1. Wipe out `vendor/` and replace it with the contents of the distribution tarball.
2. Cherry-pick any local changes from the previous version.
3. Use the command in `build/headers.rs` to generate the list of headers,
   and update that file as appropriate.
4. Check `build/config.rs` vs. `vendor/include/mbedtls/config.h`.
5. Update `Cargo.toml` version number.

# Contributing

We gratefully accept bug reports and contributions from the community.
By participating in this community, you agree to abide by [Code of Conduct](./CODE_OF_CONDUCT.md).
All contributions are covered under the Developer's Certificate of Origin (DCO).

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
have the right to submit it under the open source license
indicated in the file; or

(b) The contribution is based upon previous work that, to the best
of my knowledge, is covered under an appropriate open source
license and I have the right under that license to submit that
work with modifications, whether created in whole or in part
by me, under the same open source license (unless I am
permitted to submit under a different license), as indicated
in the file; or

(c) The contribution was provided directly to me by some other
person who certified (a), (b) or (c) and I have not modified
it.

(d) I understand and agree that this project and the contribution
are public and that a record of the contribution (including all
personal information I submit with it, including my sign-off) is
maintained indefinitely and may be redistributed consistent with
this project or the open source license(s) involved.

# License

This project is primarily distributed under the terms of the Apache License
version 2.0 and the GNU General Public License version 2, see
[LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-GPL](./LICENSE-GPL) for
details.

## A note about licensing

MbedTLS is dual-licensed Apache-2.0 / GPL-2.0+, and so are the `mbedtls` and
`mbedtls-sys-auto` crates. However, the sources are distributed in two
different single-licensed tarballs. The authors of the `mbedtls` and
`mbedtls-sys-auto` crates **do not warrant** that the two versions of the
MbedTLS code are exactly the same. This repository includes the Apache-2.0
version. Since Apache-2.0 is compatible with GPL-3.0+ this is probably not an
issue for people whishing to use mbedtls-sys in a GPL-3.0+-licensed project,
but if you want to use it in a GPL-2.0-licensed project, you should probably
manually specify the GPL-2.0 source when building.
