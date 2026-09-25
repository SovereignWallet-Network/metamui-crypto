extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;
use alloc::string::ToString;
use alloc::format;

use crate::types::{Block, Instance, Context, Argon2Type, Position, ARGON2_BLOCK_SIZE, ARGON2_QWORDS_IN_BLOCK, ARGON2_SYNC_POINTS};
use crate::block::{copy_block, xor_block_into};
use crate::compression::fill_block;
use crate::blake2b::{blake2b, blake2b_long};

// Spec constant kept for documentation (RFC 9106 §3.1 "version = 0x13"
// for Argon2v1.3). The actual version byte written to the H0 header
// lives in context.rs; this constant is here for audit cross-reference.
#[allow(dead_code)]
const ARGON2_VERSION: u32 = 0x13;

pub fn initialize(context: &Context, instance: &mut Instance) -> Result<(), String> {
    // Minimum memory: 8 * lanes (= 2 * SYNC_POINTS * lanes)
    let min_memory = 8 * context.lanes;
    let memory_blocks_raw = core::cmp::max(context.m_cost, min_memory);

    // Round down to nearest multiple of (lanes * SYNC_POINTS) per RFC 9106
    let segment_length = memory_blocks_raw / (context.lanes * ARGON2_SYNC_POINTS);
    let memory_blocks = segment_length * context.lanes * ARGON2_SYNC_POINTS;

    instance.version = context.version;
    instance.memory_blocks = memory_blocks;
    instance.pass_number = 0;
    instance.segment_length = segment_length;
    instance.slice_blocks = segment_length * ARGON2_SYNC_POINTS;
    instance.index_seed = 0;
    instance.lanes = context.lanes;
    instance.threads = context.threads;
    instance.argon2_type = context.argon2_type;

    instance.memory = vec![Block::default(); memory_blocks as usize];
    
    // Initial hashing - calculate proper buffer size
    let base_size = 4 * 10; // 10 u32 parameters (lanes, outlen, m_cost, t_cost, version, type, pwd_len, salt_len, secret_len, ad_len)
    let variable_size = context.password.len() + context.salt.len() + context.secret.len() + context.ad.len();
    let h0_buffer_size = base_size + variable_size;
    let mut h0 = vec![0u8; h0_buffer_size];
    let mut h0_len = 0;
    
    // Hash all parameters
    h0[h0_len..h0_len + 4].copy_from_slice(&context.lanes.to_le_bytes());
    h0_len += 4;
    
    h0[h0_len..h0_len + 4].copy_from_slice(&context.outlen.to_le_bytes());
    h0_len += 4;
    
    h0[h0_len..h0_len + 4].copy_from_slice(&context.m_cost.to_le_bytes());
    h0_len += 4;
    
    h0[h0_len..h0_len + 4].copy_from_slice(&context.t_cost.to_le_bytes());
    h0_len += 4;
    
    h0[h0_len..h0_len + 4].copy_from_slice(&context.version.to_le_bytes());
    h0_len += 4;
    
    h0[h0_len..h0_len + 4].copy_from_slice(&(context.argon2_type as u32).to_le_bytes());
    h0_len += 4;
    
    let pwd_len = context.password.len() as u32;
    h0[h0_len..h0_len + 4].copy_from_slice(&pwd_len.to_le_bytes());
    h0_len += 4;
    
    if !context.password.is_empty() {
        h0[h0_len..h0_len + context.password.len()].copy_from_slice(&context.password);
        h0_len += context.password.len();
    }
    
    let salt_len = context.salt.len() as u32;
    h0[h0_len..h0_len + 4].copy_from_slice(&salt_len.to_le_bytes());
    h0_len += 4;
    
    if !context.salt.is_empty() {
        h0[h0_len..h0_len + context.salt.len()].copy_from_slice(&context.salt);
        h0_len += context.salt.len();
    }
    
    let secret_len = context.secret.len() as u32;
    h0[h0_len..h0_len + 4].copy_from_slice(&secret_len.to_le_bytes());
    h0_len += 4;
    
    if !context.secret.is_empty() {
        h0[h0_len..h0_len + context.secret.len()].copy_from_slice(&context.secret);
        h0_len += context.secret.len();
    }
    
    let ad_len = context.ad.len() as u32;
    h0[h0_len..h0_len + 4].copy_from_slice(&ad_len.to_le_bytes());
    h0_len += 4;
    
    if !context.ad.is_empty() {
        h0[h0_len..h0_len + context.ad.len()].copy_from_slice(&context.ad);
        h0_len += context.ad.len();
    }
    
    // Blake2b the pre-hash using BARE Blake2b-512 (NOT H')
    // Per RFC 9106 and the reference C implementation, the initial hash
    // uses blake2b_init/update/final directly, not blake2b_long (H').
    let mut pre_hash = vec![0u8; 64];
    blake2b(&mut pre_hash, &h0[..h0_len])?;

    // Initialize first blocks of each lane
    for lane in 0..context.lanes {
        let mut block_input = vec![0u8; 72]; // pre_hash + lane + 0/1
        block_input[..64].copy_from_slice(&pre_hash);
        
        // First block (H0 || 0 || lane)
        block_input[64..68].copy_from_slice(&0u32.to_le_bytes());
        block_input[68..72].copy_from_slice(&lane.to_le_bytes());
        
        let mut block_hash = vec![0u8; ARGON2_BLOCK_SIZE];
        blake2b_long(&mut block_hash, &block_input)?;
        load_block(&mut instance.memory[lane as usize * instance.slice_blocks as usize], &block_hash);
        
        // Second block (H0 || 1 || lane)
        block_input[64..68].copy_from_slice(&1u32.to_le_bytes());
        blake2b_long(&mut block_hash, &block_input)?;
        load_block(&mut instance.memory[lane as usize * instance.slice_blocks as usize + 1], &block_hash);
    }
    
    Ok(())
}

fn load_block(block: &mut Block, input: &[u8]) {
    for i in 0..ARGON2_QWORDS_IN_BLOCK {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&input[i * 8..(i + 1) * 8]);
        block.v[i] = u64::from_le_bytes(bytes);
    }
}

pub fn fill_memory_blocks(instance: &mut Instance) -> Result<(), String> {
    if instance.threads == 1 {
        fill_memory_blocks_st(instance)
    } else {
        // For now, we'll implement single-threaded only
        fill_memory_blocks_st(instance)
    }
}

fn fill_memory_blocks_st(instance: &mut Instance) -> Result<(), String> {
    for pass in 0..instance.context.t_cost {
        instance.pass_number = pass;
        for slice in 0..ARGON2_SYNC_POINTS {
            for lane in 0..instance.lanes {
                let mut position = Position {
                    pass: pass,
                    slice: slice,
                    lane: lane,
                    index: 0,
                };
                fill_segment(&mut position, instance)?;
            }
        }
    }
    Ok(())
}

fn fill_segment(position: &mut Position, instance: &mut Instance) -> Result<(), String> {
    let data_independent = instance.argon2_type == Argon2Type::Argon2i ||
                           (instance.argon2_type == Argon2Type::Argon2id &&
                            position.pass == 0 && position.slice < ARGON2_SYNC_POINTS / 2);

    // Skip the first 2 blocks of each lane on pass 0, slice 0 (they are set by initialize)
    let first_block = if position.pass == 0 && position.slice == 0 {
        2u32
    } else {
        0u32
    };

    let segment_length = instance.segment_length;
    let lane_blocks = instance.slice_blocks; // = segment_length * SYNC_POINTS

    // Data-independent addressing state (generated on the fly)
    let mut address_block = Block::default();
    let mut input_block = Block::default();
    let zero_block = Block::default();

    if data_independent {
        input_block.v[0] = position.pass as u64;
        input_block.v[1] = position.lane as u64;
        input_block.v[2] = position.slice as u64;
        input_block.v[3] = instance.memory_blocks as u64;
        input_block.v[4] = instance.context.t_cost as u64;
        input_block.v[5] = instance.argon2_type as u64;

        // Generate first address block if starting from block 0 or 2
        if first_block == 0 || first_block == 2 {
            // Counter starts at 1
            input_block.v[6] += 1;
            fill_block(&zero_block, &input_block, &mut address_block, false);
            let temp = address_block.clone();
            fill_block(&zero_block, &temp, &mut address_block, false);
        }
    }

    let mut cur_index = (position.lane * lane_blocks +
                         position.slice * segment_length + first_block) as usize;
    let mut prev_index = if position.slice == 0 && first_block == 0 {
        // Last block in current lane
        cur_index + lane_blocks as usize - 1
    } else {
        cur_index - 1
    };

    position.index = first_block;

    for block in first_block..segment_length {
        // Get pseudo-random value
        let pseudo_rand: u64;

        if data_independent {
            let address_index = (block % ARGON2_QWORDS_IN_BLOCK as u32) as usize;
            if address_index == 0 && block != 0 {
                // Generate next batch of addresses
                input_block.v[6] += 1;
                fill_block(&zero_block, &input_block, &mut address_block, false);
                let temp = address_block.clone();
                fill_block(&zero_block, &temp, &mut address_block, false);
            }
            pseudo_rand = address_block.v[address_index];
        } else {
            pseudo_rand = instance.memory[prev_index].v[0];
        }

        // Determine reference lane
        let ref_lane = if position.pass == 0 && position.slice == 0 {
            position.lane
        } else {
            (pseudo_rand >> 32) as u32 % instance.lanes
        };

        let ref_index = index_alpha(&position, pseudo_rand as u32, ref_lane == position.lane, instance);
        let ref_offset = (ref_lane * lane_blocks + ref_index) as usize;

        // Fill the current block
        let with_xor = position.pass != 0 && instance.version == crate::types::ARGON2_VERSION_13;

        let prev_block = instance.memory[prev_index].clone();
        let ref_block = instance.memory[ref_offset].clone();
        fill_block(&prev_block, &ref_block, &mut instance.memory[cur_index], with_xor);

        prev_index = cur_index;
        cur_index += 1;
        position.index += 1;
    }

    Ok(())
}

fn index_alpha(position: &Position, pseudo_rand: u32, same_lane: bool, instance: &Instance) -> u32 {
    let reference_area_size: u32;
    let mut start_position = 0u32;
    let lane_length = instance.slice_blocks; // segment_length * SYNC_POINTS

    if position.pass == 0 {
        // First pass
        if position.slice == 0 {
            // First slice - can only reference previously computed blocks in same lane
            reference_area_size = if position.index == 0 {
                0
            } else {
                position.index - 1
            };
        } else {
            // Subsequent slices in first pass
            if same_lane {
                reference_area_size = position.slice * instance.segment_length + position.index - 1;
            } else {
                reference_area_size = position.slice * instance.segment_length -
                    if position.index == 0 { 1 } else { 0 };
            }
        }
    } else {
        // Subsequent passes - all blocks in the lane are available except current segment
        if same_lane {
            reference_area_size = lane_length - instance.segment_length + position.index - 1;
        } else {
            reference_area_size = lane_length - instance.segment_length -
                if position.index == 0 { 1 } else { 0 };
        }

        // Start position wraps around: first block after current segment
        if position.slice != ARGON2_SYNC_POINTS - 1 {
            start_position = (position.slice + 1) * instance.segment_length;
        }
    }

    // Handle edge case where reference_area_size is 0
    if reference_area_size == 0 {
        return start_position % lane_length;
    }

    // Map pseudo_rand to a position within the reference area
    let pseudo_rand_64 = pseudo_rand as u64;
    let relative_position = pseudo_rand_64.wrapping_mul(pseudo_rand_64) >> 32;
    let relative_position = reference_area_size as u64 - 1 -
        ((reference_area_size as u64).wrapping_mul(relative_position) >> 32);

    // Wrap around within the lane
    (start_position + relative_position as u32) % lane_length
}

pub fn finalize(context: &Context, instance: &Instance) -> Result<Vec<u8>, String> {
    let mut last_block = Block::default();
    
    // Start with last block of first lane
    copy_block(&instance.memory[(instance.slice_blocks - 1) as usize], &mut last_block);
    
    // XOR last blocks of remaining lanes
    for lane in 1..instance.lanes {
        let block_index = (lane * instance.slice_blocks + instance.slice_blocks - 1) as usize;
        xor_block_into(&instance.memory[block_index], &mut last_block);
    }
    
    // Hash the last block
    let mut block_bytes = vec![0u8; ARGON2_BLOCK_SIZE];
    for i in 0..ARGON2_QWORDS_IN_BLOCK {
        block_bytes[i * 8..(i + 1) * 8].copy_from_slice(&last_block.v[i].to_le_bytes());
    }
    
    let mut output = vec![0u8; context.outlen as usize];
    blake2b_long(&mut output, &block_bytes)?;
    
    Ok(output)
}

pub fn argon2_hash(
    pwd: &[u8],
    salt: &[u8],
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    hash_len: usize,
    argon2_type: Argon2Type,
    version: u32,
) -> Result<Vec<u8>, String> {
    // Validate parameters per RFC 9106
    if t_cost == 0 {
        return Err("Time cost must be at least 1".to_string());
    }
    if parallelism == 0 {
        return Err("Parallelism must be at least 1".to_string());
    }
    if m_cost < 8 * parallelism {
        return Err(format!("Memory cost {} is too small for parallelism {} (minimum {})",
                           m_cost, parallelism, 8 * parallelism));
    }
    if hash_len == 0 {
        return Err("Output length must be at least 1".to_string());
    }

    let context = Context {
        password: pwd.to_vec(),
        salt: salt.to_vec(),
        secret: vec![],
        ad: vec![],
        outlen: hash_len as u32,
        t_cost,
        m_cost,
        lanes: parallelism,
        threads: parallelism,
        version,
        argon2_type,
    };

    let mut instance = Instance::new(&context)?;

    initialize(&context, &mut instance)?;
    fill_memory_blocks(&mut instance)?;
    finalize(&context, &instance)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_argon2i_basic() {
        let password = b"password";
        let salt = b"somesalt";
        let _out = vec![0u8; 32];
        
        let result = argon2_hash(
            password,
            salt,
            2,      // t_cost
            16,     // m_cost (16 KB)
            1,      // parallelism
            32,     // hash_len
            Argon2Type::Argon2i,
            0x13,   // version
        );
        
        assert!(result.is_ok());
        let out = result.unwrap();
        // Output should be deterministic
        assert_ne!(out, vec![0u8; 32]);
    }

    #[test]
    fn test_h0_value() {
        // Verify the H0 (pre-hash) by computing it manually and comparing
        // For Argon2d(password="password", salt="somesalt", t=1, m=64, p=1, outlen=32, v=0x13)
        //
        // H0 = Blake2b-512(LE32(p) || LE32(outlen) || LE32(m) || LE32(t) || LE32(v) || LE32(type)
        //          || LE32(|pwd|) || pwd || LE32(|salt|) || salt || LE32(|secret|) || LE32(|ad|))
        //
        // Note: H0 uses BARE Blake2b-512, NOT H' (no length prefix)
        use crate::blake2b::blake2b;

        let mut h0_input = Vec::new();
        h0_input.extend_from_slice(&1u32.to_le_bytes());     // p = 1
        h0_input.extend_from_slice(&32u32.to_le_bytes());    // outlen = 32
        h0_input.extend_from_slice(&64u32.to_le_bytes());    // m = 64
        h0_input.extend_from_slice(&1u32.to_le_bytes());     // t = 1
        h0_input.extend_from_slice(&0x13u32.to_le_bytes());  // version
        h0_input.extend_from_slice(&0u32.to_le_bytes());     // type = Argon2d
        h0_input.extend_from_slice(&8u32.to_le_bytes());     // |pwd|
        h0_input.extend_from_slice(b"password");
        h0_input.extend_from_slice(&8u32.to_le_bytes());     // |salt|
        h0_input.extend_from_slice(b"somesalt");
        h0_input.extend_from_slice(&0u32.to_le_bytes());     // |secret|
        h0_input.extend_from_slice(&0u32.to_le_bytes());     // |ad|

        let mut pre_hash = vec![0u8; 64];
        blake2b(&mut pre_hash, &h0_input).unwrap();

        // H0 uses bare Blake2b-512 (no LE32 prefix)
        // Expected: cf7028aa04bf677963264c59199db12ad4f4a452682be25e419cf69260ec4383...
        let expected_h0_first8: [u8; 8] = [0xcf, 0x70, 0x28, 0xaa, 0x04, 0xbf, 0x67, 0x79];
        assert_eq!(&pre_hash[..8], &expected_h0_first8, "H0 first 8 bytes mismatch");

        // Now verify block 0 initialization
        let context = Context {
            password: b"password".to_vec(),
            salt: b"somesalt".to_vec(),
            secret: vec![],
            ad: vec![],
            outlen: 32,
            t_cost: 1,
            m_cost: 64,
            lanes: 1,
            threads: 1,
            version: 0x13,
            argon2_type: Argon2Type::Argon2d,
        };
        let mut instance = Instance::new(&context).unwrap();
        initialize(&context, &mut instance).unwrap();

        // Block0[0] with bare Blake2b H0
        assert_eq!(instance.memory[0].v[0], 0x1289280c2298ce96,
                   "Block 0 word 0 mismatch: got 0x{:016x}", instance.memory[0].v[0]);
    }

    #[test]
    fn test_blake2b_long_1024() {
        // Verify H'(1024, "test") matches reference
        use crate::blake2b::blake2b_long;
        let mut out = vec![0u8; 1024];
        blake2b_long(&mut out, b"test").unwrap();

        // Expected from RustCrypto blake2: first 16 bytes
        let expected_first = [0x8a, 0xbe, 0x7d, 0x7a, 0x11, 0xce, 0x9b, 0x75,
                              0xcc, 0x00, 0xd6, 0x8b, 0x82, 0x90, 0x4f, 0xf6];
        assert_eq!(&out[..16], &expected_first, "H'(1024, test) first 16 bytes mismatch");

        let expected_last = [0x3a, 0xe2, 0x3f, 0x6a, 0x7f, 0x11, 0x37, 0x50,
                             0x28, 0xa8, 0xcd, 0xfb, 0xa5, 0xca, 0x17, 0xbd];
        assert_eq!(&out[out.len()-16..], &expected_last, "H'(1024, test) last 16 bytes mismatch");
    }

    #[test]
    fn test_fill_block_reference() {
        // Verify fill_block by manually computing for known inputs
        // Use block 0 and block 1 from Argon2d(password, somesalt, t=1, m=64, p=1)
        // Block 2 = fill_block(block[1], block[0], false)

        let context = Context {
            password: b"password".to_vec(),
            salt: b"somesalt".to_vec(),
            secret: vec![],
            ad: vec![],
            outlen: 32,
            t_cost: 1,
            m_cost: 64,
            lanes: 1,
            threads: 1,
            version: 0x13,
            argon2_type: Argon2Type::Argon2d,
        };
        let mut instance = Instance::new(&context).unwrap();
        initialize(&context, &mut instance).unwrap();

        // Verify block 1 word 0 matches reference (bare Blake2b H0)
        assert_eq!(instance.memory[1].v[0], 0x08d24d22247bca45,
                   "Block1[0] mismatch: got 0x{:016x}", instance.memory[1].v[0]);

        // Compute block 2 manually using fill_block
        let mut block2 = Block::default();
        fill_block(&instance.memory[1], &instance.memory[0], &mut block2, false);

        // Block2 = fill_block(block[1], block[0]) -- just verify it's non-zero and deterministic
        assert_ne!(block2.v[0], 0, "Block2[0] should be non-zero");

        // Now run fill_memory_blocks and verify block 2 in memory
        let context2 = Context {
            password: b"password".to_vec(),
            salt: b"somesalt".to_vec(),
            secret: vec![],
            ad: vec![],
            outlen: 32,
            t_cost: 1,
            m_cost: 64,
            lanes: 1,
            threads: 1,
            version: 0x13,
            argon2_type: Argon2Type::Argon2d,
        };
        let mut inst2 = Instance::new(&context2).unwrap();
        initialize(&context2, &mut inst2).unwrap();
        fill_memory_blocks(&mut inst2).unwrap();

        // Block 2 in memory should match fill_block(block1, block0)
        assert_eq!(inst2.memory[2].v[0], block2.v[0],
                   "Memory block2[0] mismatch after fill");
    }
}