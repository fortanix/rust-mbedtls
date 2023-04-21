// needs to be pub for global visiblity
#[doc(hidden)]
#[cfg(any(feature = "spin_threading", feature = "rust_threading"))]
#[cfg(sys_threading_component = "custom")]
pub mod threading;

cfg_if::cfg_if! {
    if #[cfg(any(feature = "force_aesni_support", target_env = "sgx"))]
    || #[cfg(feature = "force_aesni_support")]
    {
        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn mbedtls_aesni_has_support(_what: u32) -> i32 {
            return 1;
        }

        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn mbedtls_internal_aes_encrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                                       _input: *const u8,
                                                       _output: *mut u8) -> i32 {
            panic!("AES-NI support is forced but the T-tables code was invoked")
        }

        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn mbedtls_internal_aes_decrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                                       _input: *const u8,
                                                       _output: *mut u8) -> i32 {
            panic!("AES-NI support is forced but the T-tables code was invoked")
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(sys_time_component = "custom")]
    || #[cfg(all(feature = "time", feature = "custom_gmtime_r"))]
    {
        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub unsafe extern "C" fn mbedtls_platform_gmtime_r(tt: *const mbedtls_sys::types::time_t, tp: *mut mbedtls_sys::types::tm) -> *mut mbedtls_sys::types::tm {
            use chrono::prelude::*;

            //0 means no TZ offset
            let naive = if tp.is_null() {
                return core::ptr::null_mut()
            } else {
                NaiveDateTime::from_timestamp(*tt, 0)
            };
            let utc = DateTime::<Utc>::from_utc(naive, Utc);

            let tp = &mut *tp;
            tp.tm_sec   = utc.second()   as i32;
            tp.tm_min   = utc.minute()   as i32;
            tp.tm_hour  = utc.hour()     as i32;
            tp.tm_mday  = utc.day()      as i32;
            tp.tm_mon   = utc.month0()   as i32;
            tp.tm_year  = utc.year()     as i32 - 1900;
            tp.tm_wday  = utc.weekday().num_days_from_monday() as i32;
            tp.tm_yday  = utc.ordinal0() as i32;
            tp.tm_isdst = 0;

            tp
        }
    }

    if #[cfg(sys_time_component = "custom")]
    || #[cfg(all(feature = "time", feature = "custom_time"))] {
        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub unsafe extern "C" fn mbedtls_time(tp: *mut mbedtls_sys::types::time_t) -> mbedtls_sys::types::time_t {
            let timestamp = chrono::Utc::now().timestamp() as mbedtls_sys::types::time_t;
            if !tp.is_null() {
                *tp = timestamp;
            }
            timestamp
        }
    }
}
