//! Address scheme for SLH-DSA tree hashing
//!
//! The address scheme is used to provide domain separation for the various
//! hash function calls in SLH-DSA, ensuring that the same hash function
//! can be safely used in different contexts.

/// Address structure for SLH-DSA (32 bytes total)
/// FIPS 205 layout:
/// - Bytes 0-3: Layer (4 bytes)
/// - Bytes 4-15: Tree (12 bytes)
/// - Bytes 16-19: Type (4 bytes)
/// - Bytes 20-23: Keypair (4 bytes)
/// - Bytes 24-27: Chain/Tree Height (4 bytes)
/// - Bytes 28-31: Hash/Tree Index (4 bytes)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Address {
    /// Layer address (32 bits)
    pub layer: u32,
    /// Tree address within layer (96 bits = 12 bytes, stored in u128)
    pub tree: u128,
    /// Type of address (32 bits)
    /// - 0: WOTS+ hash address
    /// - 1: WOTS+ public key compression address
    /// - 2: Hash tree address
    /// - 3: FORS tree address
    /// - 4: FORS roots compression address
    pub addr_type: u32,
    /// Usage depends on type:
    /// - WOTS+: Key pair address
    /// - Hash tree: Padding (0)
    /// - FORS: Padding (0)
    pub keypair: u32,
    /// Usage depends on type:
    /// - WOTS+: Chain address (0 to W-1)
    /// - Hash tree: Tree height
    /// - FORS tree: Tree height within FORS tree
    pub chain_tree: u32,
    /// Usage depends on type:
    /// - WOTS+: Hash address (0 to W-2)
    /// - Hash tree: Tree index
    /// - FORS tree: Tree index within FORS tree
    pub hash_keypair: u32,
}

impl Address {
    /// Create a new zeroed address
    pub fn new() -> Self {
        Default::default()
    }
    
    /// Set the layer address
    pub fn set_layer(&mut self, layer: u32) -> &mut Self {
        self.layer = layer;
        self
    }
    
    /// Set the tree address
    pub fn set_tree(&mut self, tree: u128) -> &mut Self {
        self.tree = tree;
        self
    }
    
    /// Set the type field
    pub fn set_type(&mut self, addr_type: u32) -> &mut Self {
        self.addr_type = addr_type;
        // Clear fields that should be zero for this type
        match addr_type {
            2 | 3 | 4 => self.keypair = 0, // Tree and FORS addresses
            _ => {}
        }
        self
    }

    /// Set type and clear the last 12 bytes (bytes 20-31) as per FIPS 205
    pub fn set_type_and_clear(&mut self, addr_type: u32) -> &mut Self {
        self.addr_type = addr_type;
        // Clear bytes 20-31: keypair, chain_tree, hash_keypair
        self.keypair = 0;
        self.chain_tree = 0;
        self.hash_keypair = 0;
        self
    }
    
    /// Set as WOTS+ hash address
    pub fn set_type_wots(&mut self) -> &mut Self {
        self.set_type(0)
    }
    
    /// Set as WOTS+ public key compression address
    pub fn set_type_wots_pk(&mut self) -> &mut Self {
        self.set_type(1)
    }
    
    /// Set as hash tree address
    pub fn set_type_tree(&mut self) -> &mut Self {
        self.set_type(2)
    }
    
    /// Set as FORS tree address
    pub fn set_type_fors_tree(&mut self) -> &mut Self {
        self.set_type(3)
    }
    
    /// Set as FORS roots compression address
    pub fn set_type_fors_roots(&mut self) -> &mut Self {
        self.set_type(4)
    }

    /// Set as WOTS+ PRF address (for secret key generation)
    pub fn set_type_wots_prf(&mut self) -> &mut Self {
        self.set_type(5)
    }

    /// Set the key pair address (for WOTS+)
    pub fn set_keypair(&mut self, keypair: u32) -> &mut Self {
        self.keypair = keypair;
        self
    }
    
    /// Set the chain address (for WOTS+) or tree height (for trees)
    pub fn set_chain_tree(&mut self, value: u32) -> &mut Self {
        self.chain_tree = value;
        self
    }
    
    /// Set the hash address (for WOTS+) or tree index (for trees)
    pub fn set_hash_keypair(&mut self, value: u32) -> &mut Self {
        self.hash_keypair = value;
        self
    }

    /// Set chain address (alias for set_chain_tree for WOTS+ addresses)
    pub fn set_chain_addr(&mut self, chain: u32) -> &mut Self {
        self.set_chain_tree(chain)
    }

    /// Set hash address (alias for set_hash_keypair for WOTS+ addresses)
    pub fn set_hash_addr(&mut self, hash: u32) -> &mut Self {
        self.set_hash_keypair(hash)
    }

    /// Set tree height (alias for set_chain_tree for tree addresses)
    pub fn set_tree_height(&mut self, height: u32) -> &mut Self {
        self.set_chain_tree(height)
    }

    /// Set tree index (alias for set_hash_keypair for tree addresses)
    pub fn set_tree_index(&mut self, index: u32) -> &mut Self {
        self.set_hash_keypair(index)
    }
    
    /// Copy address and set type to WOTS+
    pub fn copy_subtree_to_wots(&self) -> Self {
        let mut addr = *self;
        addr.set_type_wots();
        addr
    }
    
    /// Copy address and set type to tree
    pub fn copy_keypair_to_tree(&self) -> Self {
        let mut addr = *self;
        addr.set_type_tree();
        addr.set_tree_height(0);
        addr.set_tree_index(0);
        addr
    }
    
    /// Convert address to bytes (32 bytes total per FIPS 205)
    /// FIPS 205 layout:
    /// - Bytes 0-3: Layer (4 bytes, big-endian)
    /// - Bytes 4-15: Tree (12 bytes, big-endian)
    /// - Bytes 16-19: Type (4 bytes, big-endian)
    /// - Bytes 20-23: Keypair (4 bytes, big-endian)
    /// - Bytes 24-27: Chain/Tree Height (4 bytes, big-endian)
    /// - Bytes 28-31: Hash/Tree Index (4 bytes, big-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];

        // Bytes 0-3: Layer (4 bytes, big-endian)
        bytes[0..4].copy_from_slice(&self.layer.to_be_bytes());

        // Bytes 4-15: Tree (12 bytes from lower 96 bits of u128, big-endian)
        let tree_bytes = self.tree.to_be_bytes();
        bytes[4..16].copy_from_slice(&tree_bytes[4..16]); // Take last 12 bytes

        // Bytes 16-19: Type (4 bytes, big-endian)
        bytes[16..20].copy_from_slice(&self.addr_type.to_be_bytes());

        // Bytes 20-23: Keypair (4 bytes, big-endian)
        bytes[20..24].copy_from_slice(&self.keypair.to_be_bytes());

        // Bytes 24-27: Chain/Tree Height (4 bytes, big-endian)
        bytes[24..28].copy_from_slice(&self.chain_tree.to_be_bytes());

        // Bytes 28-31: Hash/Tree Index (4 bytes, big-endian)
        bytes[28..32].copy_from_slice(&self.hash_keypair.to_be_bytes());

        bytes
    }
    
    /// Create address from bytes (FIPS 205 layout)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        // Bytes 0-3: Layer (4 bytes, big-endian)
        let layer = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        // Bytes 4-15: Tree (12 bytes -> lower 96 bits of u128)
        let mut tree_bytes = [0u8; 16];
        tree_bytes[4..16].copy_from_slice(&bytes[4..16]);
        let tree = u128::from_be_bytes(tree_bytes);

        // Bytes 16-19: Type (4 bytes, big-endian)
        let addr_type = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);

        // Bytes 20-23: Keypair (4 bytes, big-endian)
        let keypair = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

        // Bytes 24-27: Chain/Tree Height (4 bytes, big-endian)
        let chain_tree = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);

        // Bytes 28-31: Hash/Tree Index (4 bytes, big-endian)
        let hash_keypair = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);

        Address {
            layer,
            tree,
            addr_type,
            keypair,
            chain_tree,
            hash_keypair,
        }
    }
}

/// Address type constants
pub mod addr_type {
    pub const WOTS_HASH: u32 = 0;
    pub const WOTS_PK: u32 = 1;
    pub const TREE: u32 = 2;
    pub const FORS_TREE: u32 = 3;
    pub const FORS_ROOTS: u32 = 4;
    pub const WOTS_PRF: u32 = 5;
    pub const FORS_PRF: u32 = 6;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_serialization() {
        let mut addr = Address::new();
        addr.set_layer(5)
            .set_tree(0x0123456789ABCDEF)
            .set_type_wots()
            .set_keypair(10)
            .set_chain_tree(15)
            .set_hash_keypair(20);
        
        let bytes = addr.to_bytes();
        let addr2 = Address::from_bytes(&bytes);
        
        assert_eq!(addr, addr2);
        assert_eq!(addr2.layer, 5);
        assert_eq!(addr2.tree, 0x0123456789ABCDEF);
        assert_eq!(addr2.addr_type, 0);
        assert_eq!(addr2.keypair, 10);
        assert_eq!(addr2.chain_tree, 15);
        assert_eq!(addr2.hash_keypair, 20);
    }
    
    #[test]
    fn test_address_types() {
        let mut addr = Address::new();
        
        addr.set_type_wots();
        assert_eq!(addr.addr_type, addr_type::WOTS_HASH);
        
        addr.set_type_wots_pk();
        assert_eq!(addr.addr_type, addr_type::WOTS_PK);
        
        addr.set_type_tree();
        assert_eq!(addr.addr_type, addr_type::TREE);
        
        addr.set_type_fors_tree();
        assert_eq!(addr.addr_type, addr_type::FORS_TREE);
        
        addr.set_type_fors_roots();
        assert_eq!(addr.addr_type, addr_type::FORS_ROOTS);
    }
    
    #[test]
    fn test_address_copy() {
        let mut addr = Address::new();
        addr.set_layer(3)
            .set_tree(100)
            .set_keypair(5);
        
        let wots_addr = addr.copy_subtree_to_wots();
        assert_eq!(wots_addr.layer, 3);
        assert_eq!(wots_addr.tree, 100);
        assert_eq!(wots_addr.addr_type, addr_type::WOTS_HASH);
        
        let tree_addr = addr.copy_keypair_to_tree();
        assert_eq!(tree_addr.layer, 3);
        assert_eq!(tree_addr.tree, 100);
        assert_eq!(tree_addr.addr_type, addr_type::TREE);
        assert_eq!(tree_addr.chain_tree, 0); // tree height
        assert_eq!(tree_addr.hash_keypair, 0); // tree index
    }
}