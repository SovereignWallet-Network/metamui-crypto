use metamui_argon2::core::{initialize, fill_memory_blocks};
use metamui_argon2::types::{Context, Instance, Argon2Type};

#[test]
fn test_block_filling_count() {
    let context = Context {
        password: vec![1, 2, 3, 4],
        salt: vec![5, 6, 7, 8, 9, 10, 11, 12], // RFC 9106 minimum: 8 bytes
        secret: vec![],
        ad: vec![],
        outlen: 32,
        t_cost: 1,
        m_cost: 64,
        lanes: 1,
        threads: 1,
        argon2_type: Argon2Type::Argon2d,
        version: 0x13,
    };

    let mut instance = Instance::new(&context).unwrap();
    
    // Initialize first blocks
    initialize(&context, &mut instance).unwrap();
    
    // Count non-zero blocks after initialization
    let mut init_count = 0;
    for i in 0..64 {
        if instance.memory[i].v[0] != 0 {
            init_count += 1;
        }
    }
    println!("After init: {} blocks are non-zero", init_count);
    
    // Fill memory
    fill_memory_blocks(&mut instance).unwrap();
    
    // Count non-zero blocks after filling
    let mut filled_blocks = Vec::new();
    for i in 0..64 {
        if instance.memory[i].v[0] != 0 {
            filled_blocks.push(i);
        }
    }
    
    println!("After filling: {} blocks are non-zero", filled_blocks.len());
    println!("Non-zero blocks: {:?}", filled_blocks);
    
    // Check if all blocks are filled
    if filled_blocks.len() != 64 {
        println!("ERROR: Only {} out of 64 blocks were filled!", filled_blocks.len());
        
        // Find which blocks are missing
        let mut missing = Vec::new();
        for i in 0..64 {
            if !filled_blocks.contains(&i) {
                missing.push(i);
            }
        }
        println!("Missing blocks: {:?}", missing);
    }
    
    assert_eq!(filled_blocks.len(), 64, "All 64 blocks should be filled");
}