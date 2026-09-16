/// Bit manipulation utilities

/// Bit manipulation operations
pub struct BitOps;

impl BitOps {
    /// Rotate left (32-bit)
    #[inline(always)]
    pub const fn rotate_left_u32(value: u32, n: u32) -> u32 {
        value.rotate_left(n)
    }
    
    /// Rotate right (32-bit)
    #[inline(always)]
    pub const fn rotate_right_u32(value: u32, n: u32) -> u32 {
        value.rotate_right(n)
    }
    
    /// Rotate left (64-bit)
    #[inline(always)]
    pub const fn rotate_left_u64(value: u64, n: u32) -> u64 {
        value.rotate_left(n)
    }
    
    /// Rotate right (64-bit)
    #[inline(always)]
    pub const fn rotate_right_u64(value: u64, n: u32) -> u64 {
        value.rotate_right(n)
    }
    
    /// Count leading zeros (32-bit)
    #[inline(always)]
    pub const fn leading_zeros_u32(value: u32) -> u32 {
        value.leading_zeros()
    }
    
    /// Count trailing zeros (32-bit)
    #[inline(always)]
    pub const fn trailing_zeros_u32(value: u32) -> u32 {
        value.trailing_zeros()
    }
    
    /// Count ones (population count)
    #[inline(always)]
    pub const fn count_ones_u32(value: u32) -> u32 {
        value.count_ones()
    }
    
    /// Extract bits from a value
    #[inline(always)]
    pub const fn extract_bits_u32(value: u32, start: u32, length: u32) -> u32 {
        let mask = (1u32 << length) - 1;
        (value >> start) & mask
    }
    
    /// Set bits in a value
    #[inline(always)]
    pub const fn set_bits_u32(value: u32, bits: u32, start: u32, length: u32) -> u32 {
        let mask = (1u32 << length) - 1;
        let cleared = value & !(mask << start);
        cleared | ((bits & mask) << start)
    }
    
    /// Reverse bits (32-bit)
    #[inline(always)]
    pub const fn reverse_bits_u32(value: u32) -> u32 {
        value.reverse_bits()
    }
    
    /// Reverse bits (64-bit)
    #[inline(always)]
    pub const fn reverse_bits_u64(value: u64) -> u64 {
        value.reverse_bits()
    }
    
    /// Check if power of two
    #[inline(always)]
    pub const fn is_power_of_two(value: u32) -> bool {
        value != 0 && (value & (value - 1)) == 0
    }
    
    /// Next power of two
    #[inline(always)]
    pub const fn next_power_of_two(value: u32) -> u32 {
        if value == 0 {
            return 1;
        }
        1u32 << (32 - (value - 1).leading_zeros())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rotate() {
        assert_eq!(BitOps::rotate_left_u32(0b10110000, 2), 704);
        assert_eq!(BitOps::rotate_right_u32(0b10110000, 2), 0b00101100);

        assert_eq!(BitOps::rotate_left_u64(0xFF00000000000000, 8), 0x00000000000000FF);
        assert_eq!(BitOps::rotate_right_u64(0x00000000000000FF, 8), 0xFF00000000000000);
    }
    
    #[test]
    fn test_count_bits() {
        assert_eq!(BitOps::leading_zeros_u32(0b00001111), 28);
        assert_eq!(BitOps::trailing_zeros_u32(0b11110000), 4);
        assert_eq!(BitOps::count_ones_u32(0b10101010), 4);
    }
    
    #[test]
    fn test_extract_set_bits() {
        let value = 0b11011010;
        assert_eq!(BitOps::extract_bits_u32(value, 2, 3), 0b110);
        
        let new_value = BitOps::set_bits_u32(0b11000011, 0b101, 2, 3);
        assert_eq!(new_value, 0b11010111);
    }
    
    #[test]
    fn test_reverse_bits() {
        assert_eq!(BitOps::reverse_bits_u32(0x12345678), 0x1E6A2C48);
        assert_eq!(BitOps::reverse_bits_u64(0x123456789ABCDEF0), 0x0F7B3D591E6A2C48);
    }
    
    #[test]
    fn test_power_of_two() {
        assert!(BitOps::is_power_of_two(1));
        assert!(BitOps::is_power_of_two(2));
        assert!(BitOps::is_power_of_two(4));
        assert!(BitOps::is_power_of_two(64));
        assert!(!BitOps::is_power_of_two(0));
        assert!(!BitOps::is_power_of_two(3));
        assert!(!BitOps::is_power_of_two(100));
        
        assert_eq!(BitOps::next_power_of_two(0), 1);
        assert_eq!(BitOps::next_power_of_two(1), 1);
        assert_eq!(BitOps::next_power_of_two(2), 2);
        assert_eq!(BitOps::next_power_of_two(3), 4);
        assert_eq!(BitOps::next_power_of_two(100), 128);
    }
}