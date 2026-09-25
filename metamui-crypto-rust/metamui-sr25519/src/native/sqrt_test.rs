#[cfg(test)]
mod sqrt_tests {
    use super::super::field::FieldElement;
    
    #[test]
    fn test_sqrt_simple() {
        // Test sqrt of 4 = 2
        let four = FieldElement::from_bytes(&[4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        match four.sqrt() {
            Some(two) => {
                let two_bytes = two.to_bytes();
                println!("sqrt(4) = {}", two_bytes[0]);
                assert!(two_bytes[0] == 2 || two_bytes[0] == 235); // Could be 2 or -2 (mod p)
                
                // Verify: two^2 = 4
                let check = two.square();
                assert_eq!(check, four, "sqrt(4)^2 should equal 4");
            }
            None => panic!("sqrt(4) should exist"),
        }
    }
}