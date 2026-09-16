//! Parser for NIST KAT vector files
//! 
//! This module can parse the official NIST test vector files
//! in the standard .rsp (response) format.

use crate::error::{Result, Falcon512Error};
use crate::nist_vectors::NistVector;
use alloc::vec::Vec;
use alloc::string::String;

/// Parser for NIST .rsp format files
pub struct NistVectorParser;

impl NistVectorParser {
    /// Parse a NIST .rsp file content
    pub fn parse_rsp(content: &str) -> Result<Vec<NistVector>> {
        let mut vectors = Vec::new();
        let mut current_vector: Option<PartialVector> = None;
        
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            
            // Parse key-value pairs
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let value = line[eq_pos + 1..].trim();
                
                match key {
                    "count" => {
                        // Save previous vector if exists
                        if let Some(v) = current_vector.take() {
                            if let Some(complete) = v.try_complete() {
                                vectors.push(complete);
                            }
                        }
                        // Start new vector
                        current_vector = Some(PartialVector::new(
                            value.parse().map_err(|_| Falcon512Error::InvalidParameter)?
                        ));
                    }
                    "seed" => {
                        if let Some(ref mut v) = current_vector {
                            v.seed = Some(hex_decode_rsp(value)?);
                        }
                    }
                    "mlen" => {
                        if let Some(ref mut v) = current_vector {
                            v.mlen = Some(value.parse().map_err(|_| Falcon512Error::InvalidParameter)?);
                        }
                    }
                    "msg" => {
                        if let Some(ref mut v) = current_vector {
                            v.msg = Some(hex_decode_rsp(value)?);
                        }
                    }
                    "pk" => {
                        if let Some(ref mut v) = current_vector {
                            v.pk = Some(hex_decode_rsp(value)?);
                        }
                    }
                    "sk" => {
                        if let Some(ref mut v) = current_vector {
                            v.sk = Some(hex_decode_rsp(value)?);
                        }
                    }
                    "smlen" => {
                        if let Some(ref mut v) = current_vector {
                            v.smlen = Some(value.parse().map_err(|_| Falcon512Error::InvalidParameter)?);
                        }
                    }
                    "sm" | "sig" => {
                        if let Some(ref mut v) = current_vector {
                            v.sig = Some(hex_decode_rsp(value)?);
                        }
                    }
                    _ => {
                        // Ignore unknown fields
                    }
                }
            }
        }
        
        // Save last vector
        if let Some(v) = current_vector {
            if let Some(complete) = v.try_complete() {
                vectors.push(complete);
            }
        }
        
        Ok(vectors)
    }
    
    /// Parse Falcon-specific test vectors
    pub fn parse_falcon_vectors(content: &str) -> Result<Vec<NistVector>> {
        // Falcon test vectors might have a slightly different format
        // This handles the specific format used by the Falcon reference implementation
        
        let mut vectors = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i].trim();
            
            // Look for test vector markers
            if line.starts_with("Test") || line.starts_with("COUNT") {
                let mut vector = PartialVector::new(vectors.len());
                
                // Parse the following lines for this test
                i += 1;
                while i < lines.len() {
                    let line = lines[i].trim();
                    
                    if line.is_empty() {
                        break;
                    }
                    
                    if let Some(eq_pos) = line.find('=') {
                        let key = line[..eq_pos].trim().to_lowercase();
                        let value = line[eq_pos + 1..].trim();
                        
                        match key.as_str() {
                            "seed" | "entropy" => {
                                vector.seed = Some(hex_decode_rsp(value)?);
                            }
                            "message" | "msg" => {
                                vector.msg = Some(hex_decode_rsp(value)?);
                            }
                            "pk" | "publickey" => {
                                vector.pk = Some(hex_decode_rsp(value)?);
                            }
                            "sk" | "secretkey" | "privatekey" => {
                                vector.sk = Some(hex_decode_rsp(value)?);
                            }
                            "signature" | "sig" => {
                                vector.sig = Some(hex_decode_rsp(value)?);
                            }
                            _ => {}
                        }
                    }
                    
                    i += 1;
                }
                
                if let Some(complete) = vector.try_complete() {
                    vectors.push(complete);
                }
            } else {
                i += 1;
            }
        }
        
        Ok(vectors)
    }
}

/// Partial vector being built during parsing
struct PartialVector {
    count: usize,
    seed: Option<Vec<u8>>,
    mlen: Option<usize>,
    msg: Option<Vec<u8>>,
    pk: Option<Vec<u8>>,
    sk: Option<Vec<u8>>,
    smlen: Option<usize>,
    sig: Option<Vec<u8>>,
}

impl PartialVector {
    fn new(count: usize) -> Self {
        Self {
            count,
            seed: None,
            mlen: None,
            msg: None,
            pk: None,
            sk: None,
            smlen: None,
            sig: None,
        }
    }
    
    fn try_complete(self) -> Option<NistVector> {
        // For keygen tests, we only need seed
        let seed = self.seed.unwrap_or_else(|| vec![0u8; 48]);
        
        // For sign/verify tests, we need at least message
        let msg = self.msg.unwrap_or_default();
        
        // Public and secret keys (use defaults if not provided)
        let pk = self.pk.unwrap_or_else(|| vec![0u8; 897]);
        let sk = self.sk.unwrap_or_else(|| vec![0u8; 2305]);
        
        // Signature (use default if not provided)
        let sig = self.sig.unwrap_or_else(|| vec![0u8; 666]);
        
        Some(NistVector {
            count: self.count,
            seed,
            msg,
            pk,
            sk,
            sig,
        })
    }
}

/// Decode hex string from RSP format (handles spacing)
fn hex_decode_rsp(hex: &str) -> Result<Vec<u8>> {
    // Remove all whitespace
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    
    if hex.len() % 2 != 0 {
        return Err(Falcon512Error::InvalidParameter);
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| Falcon512Error::InvalidParameter)?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Load vectors from a file path (when std is available)
#[cfg(feature = "std")]
pub fn load_vectors_from_file(path: &str) -> Result<Vec<NistVector>> {
    use std::fs;
    
    let content = fs::read_to_string(path)
        .map_err(|_| Falcon512Error::InvalidParameter)?;
    
    // Try different parsers
    if path.ends_with(".rsp") {
        NistVectorParser::parse_rsp(&content)
    } else {
        NistVectorParser::parse_falcon_vectors(&content)
    }
}

/// Create sample test vectors for development
pub fn create_sample_vectors() -> Vec<NistVector> {
    vec![
        // Empty message test
        NistVector {
            count: 0,
            seed: vec![0x01; 48],
            msg: vec![],
            pk: vec![0x00; 897],
            sk: vec![0x00; 1281],
            sig: vec![0x00; 666],
        },
        // Short message test
        NistVector {
            count: 1,
            seed: vec![0x02; 48],
            msg: b"test message".to_vec(),
            pk: vec![0x00; 897],
            sk: vec![0x00; 1281],
            sig: vec![0x00; 666],
        },
        // Long message test
        NistVector {
            count: 2,
            seed: vec![0x03; 48],
            msg: vec![0xAA; 1000],
            pk: vec![0x00; 897],
            sk: vec![0x00; 1281],
            sig: vec![0x00; 666],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hex_decode_rsp() {
        // Test basic hex decoding
        assert_eq!(hex_decode_rsp("00").unwrap(), vec![0x00]);
        assert_eq!(hex_decode_rsp("FF").unwrap(), vec![0xFF]);
        assert_eq!(hex_decode_rsp("0102").unwrap(), vec![0x01, 0x02]);
        
        // Test with spaces (should be handled)
        assert_eq!(hex_decode_rsp("01 02").unwrap(), vec![0x01, 0x02]);
        assert_eq!(hex_decode_rsp("01 02 03").unwrap(), vec![0x01, 0x02, 0x03]);
    }
    
    #[test]
    fn test_parse_simple_rsp() {
        let content = r#"
# Test vectors for Falcon-512
count = 0
seed = 0123456789ABCDEF
mlen = 0
msg = 
pk = 0904
sk = 0804
smlen = 666
sm = 3044

count = 1
seed = FEDCBA9876543210
mlen = 3
msg = 616263
pk = 0904
sk = 0804
smlen = 666
sm = 3044
"#;
        
        let vectors = NistVectorParser::parse_rsp(content).unwrap();
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].count, 0);
        assert_eq!(vectors[0].msg.len(), 0);
        assert_eq!(vectors[1].count, 1);
        assert_eq!(vectors[1].msg, vec![0x61, 0x62, 0x63]);
    }
}