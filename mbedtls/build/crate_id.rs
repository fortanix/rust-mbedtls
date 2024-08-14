use std::fmt;

pub struct StableCrateId(u64);

impl StableCrateId {
    pub fn new(
        crate_name: &str,
        is_exe: bool,
        mut metadata: Vec<String>,
        cfg_version: String,
    ) -> StableCrateId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        crate_name.hash(&mut hasher);

        metadata.sort();
        metadata.dedup();

        hasher.write(b"metadata");
        for s in &metadata {
            hasher.write_usize(s.len());
            hasher.write(s.as_bytes());
        }

        hasher.write(if is_exe { b"exe" } else { b"lib" });

        hasher.write(cfg_version.as_bytes());

        StableCrateId(hasher.finish() as u64)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

// Implement the LowerHex trait for StableCrateId
impl fmt::LowerHex for StableCrateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::Display for StableCrateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Implement the formatting logic here
        // Example: Display the inner value as a hexadecimal string
        write!(f, "{:x}", self.0)
    }
}