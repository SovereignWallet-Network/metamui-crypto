/// Endianness conversion utilities


/// Endianness conversion operations
pub struct Endianness;

impl Endianness {
    /// Convert u32 from big-endian bytes
    #[inline(always)]
    pub const fn u32_from_be_bytes(bytes: [u8; 4]) -> u32 {
        u32::from_be_bytes(bytes)
    }
    
    /// Convert u32 to big-endian bytes
    #[inline(always)]
    pub const fn u32_to_be_bytes(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }
    
    /// Convert u32 from little-endian bytes
    #[inline(always)]
    pub const fn u32_from_le_bytes(bytes: [u8; 4]) -> u32 {
        u32::from_le_bytes(bytes)
    }
    
    /// Convert u32 to little-endian bytes
    #[inline(always)]
    pub const fn u32_to_le_bytes(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }
    
    /// Convert u64 from big-endian bytes
    #[inline(always)]
    pub const fn u64_from_be_bytes(bytes: [u8; 8]) -> u64 {
        u64::from_be_bytes(bytes)
    }
    
    /// Convert u64 to big-endian bytes
    #[inline(always)]
    pub const fn u64_to_be_bytes(value: u64) -> [u8; 8] {
        value.to_be_bytes()
    }
    
    /// Convert u64 from little-endian bytes
    #[inline(always)]
    pub const fn u64_from_le_bytes(bytes: [u8; 8]) -> u64 {
        u64::from_le_bytes(bytes)
    }
    
    /// Convert u64 to little-endian bytes
    #[inline(always)]
    pub const fn u64_to_le_bytes(value: u64) -> [u8; 8] {
        value.to_le_bytes()
    }
    
    /// Read u32 from byte slice (big-endian)
    pub fn read_u32_be(bytes: &[u8]) -> Option<u32> {
        if bytes.len() < 4 {
            return None;
        }
        let array: [u8; 4] = bytes[..4].try_into().ok()?;
        Some(Self::u32_from_be_bytes(array))
    }
    
    /// Read u32 from byte slice (little-endian)
    pub fn read_u32_le(bytes: &[u8]) -> Option<u32> {
        if bytes.len() < 4 {
            return None;
        }
        let array: [u8; 4] = bytes[..4].try_into().ok()?;
        Some(Self::u32_from_le_bytes(array))
    }
    
    /// Read u64 from byte slice (big-endian)
    pub fn read_u64_be(bytes: &[u8]) -> Option<u64> {
        if bytes.len() < 8 {
            return None;
        }
        let array: [u8; 8] = bytes[..8].try_into().ok()?;
        Some(Self::u64_from_be_bytes(array))
    }
    
    /// Read u64 from byte slice (little-endian)
    pub fn read_u64_le(bytes: &[u8]) -> Option<u64> {
        if bytes.len() < 8 {
            return None;
        }
        let array: [u8; 8] = bytes[..8].try_into().ok()?;
        Some(Self::u64_from_le_bytes(array))
    }
    
    /// Write u32 to byte slice (big-endian)
    pub fn write_u32_be(bytes: &mut [u8], value: u32) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        bytes[..4].copy_from_slice(&Self::u32_to_be_bytes(value));
        true
    }
    
    /// Write u32 to byte slice (little-endian)
    pub fn write_u32_le(bytes: &mut [u8], value: u32) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        bytes[..4].copy_from_slice(&Self::u32_to_le_bytes(value));
        true
    }
    
    /// Write u64 to byte slice (big-endian)
    pub fn write_u64_be(bytes: &mut [u8], value: u64) -> bool {
        if bytes.len() < 8 {
            return false;
        }
        bytes[..8].copy_from_slice(&Self::u64_to_be_bytes(value));
        true
    }
    
    /// Write u64 to byte slice (little-endian)
    pub fn write_u64_le(bytes: &mut [u8], value: u64) -> bool {
        if bytes.len() < 8 {
            return false;
        }
        bytes[..8].copy_from_slice(&Self::u64_to_le_bytes(value));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_u32_conversions() {
        let value = 0x12345678u32;
        
        // Big-endian
        let be_bytes = Endianness::u32_to_be_bytes(value);
        assert_eq!(be_bytes, [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(Endianness::u32_from_be_bytes(be_bytes), value);
        
        // Little-endian
        let le_bytes = Endianness::u32_to_le_bytes(value);
        assert_eq!(le_bytes, [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(Endianness::u32_from_le_bytes(le_bytes), value);
    }
    
    #[test]
    fn test_u64_conversions() {
        let value = 0x123456789ABCDEF0u64;
        
        // Big-endian
        let be_bytes = Endianness::u64_to_be_bytes(value);
        assert_eq!(be_bytes, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
        assert_eq!(Endianness::u64_from_be_bytes(be_bytes), value);
        
        // Little-endian
        let le_bytes = Endianness::u64_to_le_bytes(value);
        assert_eq!(le_bytes, [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(Endianness::u64_from_le_bytes(le_bytes), value);
    }
    
    #[test]
    fn test_read_write_slices() {
        let mut buffer = vec![0u8; 16];
        
        // Write and read u32
        assert!(Endianness::write_u32_be(&mut buffer[0..4], 0x12345678));
        assert_eq!(Endianness::read_u32_be(&buffer[0..4]), Some(0x12345678));
        
        assert!(Endianness::write_u32_le(&mut buffer[4..8], 0x12345678));
        assert_eq!(Endianness::read_u32_le(&buffer[4..8]), Some(0x12345678));
        
        // Write and read u64
        assert!(Endianness::write_u64_be(&mut buffer[0..8], 0x123456789ABCDEF0));
        assert_eq!(Endianness::read_u64_be(&buffer[0..8]), Some(0x123456789ABCDEF0));
        
        assert!(Endianness::write_u64_le(&mut buffer[8..16], 0x123456789ABCDEF0));
        assert_eq!(Endianness::read_u64_le(&buffer[8..16]), Some(0x123456789ABCDEF0));
        
        // Test insufficient buffer size
        let small_buffer = vec![0u8; 3];
        assert_eq!(Endianness::read_u32_be(&small_buffer), None);
        assert_eq!(Endianness::read_u64_be(&small_buffer), None);
    }
}