//! CLI configuration

pub struct Config {
    pub ipfs_endpoint: String,
    pub substrate_endpoint: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ipfs_endpoint: "http://127.0.0.1:5001".to_string(),
            substrate_endpoint: "ws://127.0.0.1:9944".to_string(),
        }
    }
}
