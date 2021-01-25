use std::collections::{HashMap, HashSet};
use std::env;

pub struct Features {
    platform_components: HashMap<&'static str, HashSet<&'static str>>,
    automatic_features: HashSet<&'static str>,
}

lazy_static! {
    pub static ref FEATURES: Features = {
        let mut ret = Features {
            platform_components: HashMap::new(),
            automatic_features: HashSet::new(),
        };

        ret.init();

        ret
    };
}

impl Features {
    fn init(&mut self) {
        if env_have_target_cfg("env", "sgx") {
            self.automatic_features.insert("custom_has_support");
            self.automatic_features.insert("aes_alt");
            self.automatic_features.insert("aesni");
        }
        self.automatic_features.insert("c_compiler");

        // deprecated, needed for backcompat
        let have_custom_threading = self.have_feature("custom_threading");
        let have_custom_gmtime_r = self.have_feature("custom_gmtime_r");

        if !self.have_feature("std") ||
            env_have_target_cfg("env", "sgx") ||
            env_have_target_cfg("os", "none") {
            self.with_feature("c_compiler").unwrap().insert("freestanding");
        }
        if let Some(components) = self.with_feature("threading") {
            if !have_custom_threading && env_have_target_cfg("family", "unix") {
                components.insert("pthread");
            } else {
                components.insert("custom");
            }
        }
        if let Some(components) = self.with_feature("std") {
            if env_have_target_cfg("family", "unix") {
                components.insert("net");
                components.insert("fs");
                components.insert("entropy");
            }
        }
        if let Some(components) = self.with_feature("time") {
            if !have_custom_gmtime_r && env_have_target_cfg("family", "unix") {
                components.insert("libc");
            } else {
                components.insert("custom");
            }
        }

        for (feature, components) in &self.platform_components {
            for component in components {
                println!(r#"cargo:rustc-cfg={}_component="{}""#, feature, component);
            }
        }
        println!("cargo:platform-components={}",
            self.platform_components.iter().flat_map(|(feature, components)| {
                components.iter().map(move |component| format!(r#"{}_component={}"#, feature, component))
            } ).collect::<Vec<_>>().join(",")
        );
    }

    fn with_feature(&mut self, feature: &'static str) -> Option<&mut HashSet<&'static str>> {
        if self.have_feature(feature) {
            Some(self.platform_components.entry(feature).or_insert_with(HashSet::new))
        } else {
            None
        }
    }

    pub fn have_platform_component(&self, feature: &'static str, component: &'static str) -> bool {
        self.platform_components.get(feature).map_or(false, |feat| feat.contains(component))
    }

    pub fn have_feature(&self, feature: &'static str) -> bool {
        self.automatic_features.contains(feature) || env_have_feature(feature)
    }
}

fn env_have_target_cfg(var: &'static str, value: &'static str) -> bool {
    let env = format!("CARGO_CFG_TARGET_{}", var).to_uppercase().replace("-", "_");
    env::var_os(env).map_or(false, |s| s == value)
}

fn env_have_feature(feature: &'static str) -> bool {
    let env = format!("CARGO_FEATURE_{}", feature).to_uppercase().replace("-", "_");
    env::var_os(env).is_some()
}
