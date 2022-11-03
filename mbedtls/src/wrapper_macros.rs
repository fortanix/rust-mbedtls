/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

macro_rules! as_item {
    ($i:item) => {
        $i
    };
}

macro_rules! callback {
    //{ ($($arg:ident: $ty:ty),*) -> $ret:ty } => {
    //};
    { $n:ident, $m:ident($($arg:ident: $ty:ty),*) -> $ret:ty } => {
        pub trait $n: Send + Sync {
            unsafe extern "C" fn call_mut(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized;

            fn data_ptr_mut(&mut self) -> *mut ::mbedtls_sys::types::raw_types::c_void;
        }

        impl<F> $n for F where F: FnMut($($ty),*) -> $ret + Send + Sync {
            unsafe extern "C" fn call_mut(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized {
                (&mut*(user_data as *mut F))($($arg),*)
            }

            fn data_ptr_mut(&mut self) -> *mut ::mbedtls_sys::types::raw_types::c_void {
                self as *const F as *mut _
            }
        }

        pub trait $m: Send + Sync {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized;

            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void;
        }

        impl<F> $m for F where F: Fn($($ty),*) -> $ret + Send + Sync {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized {
                (&mut*(user_data as *mut F))($($arg),*)
            }

            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void {
                self as *const F as *mut _
            }
        }
    };
    ($t:ident: $($bound:tt)*) => {
        pub trait $t: $($bound)* + Send + Sync {}

        impl<F: $($bound)* + Send + Sync> $t for F {}
    };
}

macro_rules! define {
    // When using members, careful with UnsafeFrom, the data casted back must have been allocated on rust side.
    { #[c_ty($inner:ident)] $(#[$m:meta])* struct $name:ident$(<$l:tt>)* $({ $($(#[$mm:meta])* $member:ident: $member_type:ty,)* })?; $($defs:tt)* } => {
        define_struct!(define $(#[$m])* struct $name $(lifetime $l)* inner $inner members $($($(#[$mm])* $member: $member_type,)*)*);
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    // Do not use UnsafeFrom with 'c_box_ty'. That is currently not supported as its not needed anywhere, support may be added in the future if needed anywhere.
    { #[c_box_ty($inner:ident)] $(#[$m:meta])* struct $name:ident$(<$l:tt>)* $({ $($(#[$mm:meta])* $member:ident: $member_type:ty,)* })?; $($defs:tt)* } => {
        define_struct!(define_box $(#[$m])* struct $name $(lifetime $l)* inner $inner members $($($(#[$mm])* $member: $member_type,)*)*);
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    {                   #[c_ty($raw:ty)] $(#[$m:meta])* enum $n:ident { $(#[$doc:meta] $rust:ident = $c:ident,)* } } => { define_enum!(                  $(#[$m])* enum $n ty $raw : $(doc ($doc) rust $rust c $c),*); };
    {                   #[c_ty($raw:ty)] $(#[$m:meta])* enum $n:ident { $(             $rust:ident = $c:ident,)* } } => { define_enum!(                  $(#[$m])* enum $n ty $raw : $(doc (    ) rust $rust c $c),*); };
    { #[non_exhaustive] #[c_ty($raw:ty)] $(#[$m:meta])* enum $n:ident { $(#[$doc:meta] $rust:ident = $c:ident,)* } } => { define_enum!(#[non_exhaustive] $(#[$m])* enum $n ty $raw : $(doc ($doc) rust $rust c $c),*); };
    { #[non_exhaustive] #[c_ty($raw:ty)] $(#[$m:meta])* enum $n:ident { $(             $rust:ident = $c:ident,)* } } => { define_enum!(#[non_exhaustive] $(#[$m])* enum $n ty $raw : $(doc (    ) rust $rust c $c),*); };
}

macro_rules! define_enum {
    {#[non_exhaustive] $(#[$m:meta])* enum $n:ident ty $raw:ty : $(doc ($($doc:meta)*) rust $rust:ident c $c:ident),*} => {
        $(#[$m])*
        pub enum $n {
            $($(#[$doc])* $rust,)*
            // Stable-Rust equivalent of `#[non_exhaustive]` attribute. This
            // value should never be used by users of this crate!
            #[doc(hidden)]
            __Nonexhaustive,
        }

        impl Into<$raw> for $n {
            fn into(self) -> $raw {
                match self {
                    $($n::$rust => $c,)*
                    $n::__Nonexhaustive => unreachable!("__Nonexhaustive value should not be instantiated"),
                }
            }
        }
    };
    {$(#[$m:meta])* enum $n:ident ty $raw:ty : $(doc ($($doc:meta)*) rust $rust:ident c $c:ident),*} => {
        $(#[$m])*
        pub enum $n {
            $($(#[$doc])* $rust,)*
        }

        impl Into<$raw> for $n {
            fn into(self) -> $raw {
                match self {
                    $($n::$rust => $c,)*
                }
            }
        }
    };
}

macro_rules! define_struct {
    { define $(#[$m:meta])* struct $name:ident $(lifetime $l:tt)* inner $inner:ident members $($(#[$mm:meta])* $member:ident: $member_type:ty,)* } => {
        as_item!(
        #[allow(dead_code)]
        $(#[$m])*
        pub struct $name<$($l)*> {
            inner: ::mbedtls_sys::$inner,
            $(r: ::core::marker::PhantomData<&$l ()>,)*
            $($(#[$mm])* $member: $member_type,)*
        }
        );

        as_item!(
        #[allow(dead_code)]
        impl<$($l)*> $name<$($l)*> {
            pub(crate) fn into_inner(self) -> ::mbedtls_sys::$inner {
                let inner = self.inner;
                ::core::mem::forget(self);
                inner
            }

            pub(crate) fn handle(&self) -> &::mbedtls_sys::$inner {
                &self.inner
            }

            pub(crate) fn handle_mut(&mut self) -> &mut ::mbedtls_sys::$inner {
                &mut self.inner
            }
        }
        );

        as_item!(
        unsafe impl<$($l)*> Send for $name<$($l)*> {}
        );
    };

    { define_box $(#[$m:meta])* struct $name:ident $(lifetime $l:tt)* inner $inner:ident members $($(#[$mm:meta])* $member:ident: $member_type:ty,)* } => {
        as_item!(
        #[allow(dead_code)]
        $(#[$m])*
        pub struct $name<$($l)*> {
            inner: Box<::mbedtls_sys::$inner>,
            $(r: ::core::marker::PhantomData<&$l ()>,)*
            $($(#[$mm])* $member: $member_type,)*
        }
        );

        as_item!(
        #[allow(dead_code)]
        impl<$($l)*> $name<$($l)*> {
            pub(crate) fn handle(&self) -> &::mbedtls_sys::$inner {
                &*self.inner
            }

            pub(crate) fn handle_mut(&mut self) -> &mut ::mbedtls_sys::$inner {
                &mut *self.inner
            }
        }
        );

        as_item!(
        unsafe impl<$($l)*> Send for $name<$($l)*> {}
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> const init: fn() -> Self = $ctor:ident $({ $($member:ident: $member_init:expr,)* })?; $($defs:tt)* } => {
        define_struct!(init $name () init $ctor $(lifetime $l)* members $($($member: $member_init,)*)* );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> pub const new: fn() -> Self = $ctor:ident $({ $($member:ident: $member_init:expr,)* })?; $($defs:tt)* } => {
        define_struct!(init $name (pub) new $ctor $(lifetime $l)* members $($($member: $member_init,)*)* );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { init $name:ident ($($vis:tt)*) $new:ident $ctor:ident $(lifetime $l:tt)* members $($member:ident: $member_init:expr,)*  } => {
        as_item!(
        #[allow(dead_code)]
        impl<$($l)*> $name<$($l)*> {
            $($vis)* fn $new() -> Self {
                let mut inner = ::core::mem::MaybeUninit::uninit();
                let inner = unsafe {
                    ::mbedtls_sys::$ctor(inner.as_mut_ptr());
                    inner.assume_init()
                };
                $name{
                    inner,
                    $(r: ::core::marker::PhantomData::<&$l _>,)*
                    $($member: $member_init,)*
                }
            }
        }
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> const drop: fn(&mut Self) = $dtor:ident; $($defs:tt)* } => {
        define_struct!(drop $name dtor $dtor $(lifetime $l)* );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { drop $name:ident dtor $dtor:ident $(lifetime $l:tt)* } => {
        as_item!(
        impl<$($l)*> Drop for $name<$($l)*> {
            fn drop(&mut self) {
                unsafe{::mbedtls_sys::$dtor(self.handle_mut())};
            }
        }
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> impl<$l2:tt> Into<ptr> {} $($defs:tt)* } => {
        define_struct!(into $name inner $inner $(lifetime $l)* lifetime2 $l2 );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { into $name:ident inner $inner:ident $(lifetime $l:tt)* lifetime2 $l2:tt } => {
        as_item!(
        impl<$l2,$($l),*> Into<*const $inner> for &$l2 $name<$($l)*> {
            fn into(self) -> *const $inner {
                self.handle()
            }
        }
        );

        as_item!(
        impl<$l2,$($l),*> Into<*mut $inner> for &$l2 mut $name<$($l)*> {
            fn into(self) -> *mut $inner {
                self.handle_mut()
            }
        }
        );
        as_item!(
        impl<$($l),*> $name<$($l)*> {
            /// Needed for compatibility with mbedtls - where we could pass
            /// `*const` but function signature requires `*mut`
            #[allow(dead_code)]
            pub(crate) unsafe fn inner_ffi_mut(&self) -> *mut $inner {
                self.handle() as *const _ as *mut $inner
            }
        }
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> impl<$l2:tt> UnsafeFrom<ptr> {} $($defs:tt)* } => {
        define_struct!(unsafe_from $name inner $inner $(lifetime $l)* lifetime2 $l2 );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { unsafe_from $name:ident inner $inner:ident $(lifetime $l:tt)* lifetime2 $l2:tt } => {
        as_item!(
        impl<$l2,$($l),*> crate::private::UnsafeFrom<*const $inner> for &$l2 $name<$($l)*> {
            unsafe fn from(ptr: *const $inner) -> Option<Self> {
                (ptr as *const $name).as_ref()
            }
        }
        );

        as_item!(
        impl<$l2,$($l),*> crate::private::UnsafeFrom<*mut $inner> for &$l2 mut $name<$($l)*> {
            unsafe fn from(ptr: *mut $inner) -> Option<Self> {
                (ptr as *mut $name).as_mut()
            }
        }
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> } => {};
    { lifetime $l:tt } => {};
}

macro_rules! setter {
    { $(#[$m:meta])* $rfn:ident($n:ident : $rty:ty) = $cfn:ident } => {
        $(#[$m])*
        pub fn $rfn(&mut self, $n: $rty) {
            unsafe{::mbedtls_sys::$cfn(self.into(),$n.into())}
        }
    }
}

macro_rules! getter {
    { $(#[$m:meta])* $rfn:ident() -> $rty:ty = .$cfield:ident } => {
        $(#[$m])*
        pub fn $rfn(&self) -> $rty {
            self.inner.$cfield.into()
        }
    };
    { $(#[$m:meta])* $rfn:ident() -> $rty:ty = fn $cfn:ident } => {
        $(#[$m])*
        pub fn $rfn(&self) -> $rty {
            unsafe{::mbedtls_sys::$cfn(self.into()).into()}
        }
    };
}



#[cfg(test)]
mod tests {
    use crate::tests::{TestTrait, Testable};

    callback!(RustTest: Fn() -> ());
    callback!(NativeTestMut,NativeTest() -> ());

    impl<T: RustTest> Testable<dyn RustTest> for T {}
    impl<T: NativeTest> Testable<dyn NativeTest> for T {}
    impl<T: NativeTestMut> Testable<dyn NativeTestMut> for T {}

    #[test]
    fn callback_sync() {
        fn test_closure<T: RustTest>() {
            assert!(TestTrait::<dyn Send + Sync, T>::new().impls_trait(), "RustTest should be Send + Sync");
        }
        fn test_native_closure<T: NativeTest>() {
            assert!(TestTrait::<dyn Send + Sync, T>::new().impls_trait(), "NativeTest should be Send + Sync");
        }
        fn test_native_mut_closure<T: NativeTestMut>() {
            assert!(TestTrait::<dyn Send + Sync, T>::new().impls_trait(), "NativeTestMut should be Send + Sync");
        }

        test_closure::<fn()->()>();
        test_native_closure::<fn()->()>();
        test_native_mut_closure::<fn()->()>();

        assert!(!TestTrait::<dyn RustTest, &dyn Fn()->()>::new().impls_trait(), "non-Sync closure shouldn't be RustTest");
        assert!(TestTrait::<dyn RustTest, &(dyn Fn()->() + Send + Sync)>::new().impls_trait(), "Sync closure should be RustTest");
        assert!(!TestTrait::<dyn NativeTest, &dyn Fn()->()>::new().impls_trait(), "non-Sync closure shouldn't be NativeTest");
        assert!(TestTrait::<dyn NativeTest, &(dyn Fn()->() + Send + Sync)>::new().impls_trait(), "Sync closure should be NativeTest");
        assert!(!TestTrait::<dyn NativeTestMut, &dyn Fn()->()>::new().impls_trait(), "non-Sync closure shouldn't be NativeTestMut");
        assert!(TestTrait::<dyn NativeTestMut, &(dyn Fn()->() + Send + Sync)>::new().impls_trait(), "Sync closure should be NativeTestMut");
    }
}
