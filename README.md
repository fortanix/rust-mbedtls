# mbedtls

This is an idiomatic Rust wrapper for mbedTLS, allowing you to use mbedTLS with 
only safe code while being able to use such great Rust features like error 
handling and closures.

Additionally, building on mbedTLS's focus on embedded use, this crate can be 
used in a no_std environment.

## Building

This crate depends on the mbedtls-sys-auto crate, see below for build details.

### Features

This is a list of the Cargo features available for mbedtls-sys. Features in 
**bold** are enabled by default.

* *core_io* On no_std, you must enable this feature. It will supply the I/O
            Read and Write traits.
* **collections** Enable functions using `String` and `Vec`. On no_std, you 
                  must also enable the *core_io_collections* feature.
* *force_aesni_support* mbedTLS normally uses runtime detection of AES-NI 
						support. With this feature, always use AES-NI. This 
						will result in undefined instruction exceptions on 
						unsupported processors.
* *pthread* Enable mutex synchronization using pthreads.
* *rdrand* Enable the RDRAND random number generator.
* *spin_threading* Enable mutex synchronization using the spin crate.
* **std** If this feature is not enabled, this crate is a no_std crate. (An 
		  allocator is *required*) The necessary C functions to make mbedTLS 
		  work without libc will be provided.

PRs adding new features are encouraged.

# mbedtls-sys-auto

Unfortunately, between the time I developed this crate and the time I got 
around to publishing it, someone else already took the mbedtls-sys crate name, 
hence the different name.

To use this crate, you will need to have **clang** and **cmake** installed, see 
below for details.

## Configuring and linking mbedTLS

mbedTLS has a plethora of compile-time configuration options that significantly 
impact what functionality is available. To make sure Rust's view of mbedTLS 
matches up with what's built in C, mbedTLS must be configured using Cargo 
features (see next section) and built using mbedtls-sys's build script.

The mbedtls-sys crate includes the mbedTLS source code, the mbedTLS version 
will have the same major.minor version as the crate. Instead of using the 
provided source, you can specify the path to your own source tree using the 
`RUST_MBEDTLS_SYS_SOURCE` environment variable. It is not recommended to use a 
custom source that is based on a different version of mbedTLS than the one 
provided in the crate.

The build script will perform the following steps:
1. generate an appropriate config.h (any existing config.h is ignored),
2. compile a statically-linked mbedTLS, this requires cmake to be installed,
3. generate Rust bindings based on the configuration, this requires clang to be
   installed.

### Features

This is a list of the Cargo features available for mbedtls-sys. Features in 
**bold** are enabled by default.

* *custom_has_support* Override runtime feature detection. In a dependent 
					   crate, you must define the functions 
					   `mbedtls_aesni_has_support` and 
					   `mbedtls_padlock_has_support` following the mbedTLS 
					   function signatures.
* *custom_printf* Provide a custom printf implementation. printf is only used 
				  for the self tests. In a dependent crate, you must define the 
				  `mbedtls_printf` function with the standard printf signature.
* *custom_threading* Provide a custom threading implementation. In a dependent 
					 crate, you must define the functions `mbedtls_mutex_init`, 
					 `mbedtls_mutex_free`, `mbedtls_mutex_lock`, and 
					 `mbedtls_mutex_unlock` following the mbedTLS function 
					 signatures.
* *havege* Enable the Hardware Volatile Entropy Gathering and Expansion 
           (HAVEGE) algorithm.
* *pkcs11* Enable PKCS#11 support. This requires pkcs11-helper to be installed.
* **pthread** Enable threading support using pthreads.
* **std** If this feature is not enabled, this crate is a no_std crate. In a 
		  no_std configuration without libc, you need to provide your own 
		  versions of the following standard C functions: calloc/free, and 
		  strstr/strlen/strncpy/strncmp/strcmp/snprintf, and 
		  memmove/memcpy/memcmp/memset, and rand/printf. For printf, you can 
		  optionally use the `custom_printf` feature.
* **time** Enable time support.
* **zlib** Enable zlib support.

For the complete mapping of features to config.h defines, see 
[mbedtls-sys/build/config.rs]. PRs adding new features are encouraged.

## A note about licensing

mbedTLS is dual-licensed Apache-2.0 / GPL-2.0+, and so is the mbedtls-sys 
crate. However, the sources are distributed in two different single-licensed 
tarballs. The authors of the mbedtls-sys crate **do not warrant** that the two 
versions of the mbedTLS code are exactly the same. This crate includes the 
Apache-2.0 version. Since Apache-2.0 is compatible with GPL-3.0+ this is 
probably not an issue for people whishing to use mbedtls-sys in a 
GPL-3.0+-licensed project, but if you want to use it in a GPL-2.0-licensed 
project, you should probably manually specify the GPL-2.0 source when building.
