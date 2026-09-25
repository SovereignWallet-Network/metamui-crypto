#[cfg(test)]
mod scalar_mul_tests {
    use super::super::curve::EdwardsPoint;
    // use super::super::field::FieldElement; // TODO: Re-enable when needed
    
    #[test]
    fn test_scalar_mul_invariants() {
        println!("Testing scalar multiplication step by step...\n");
        
        // Get the base point
        let base = EdwardsPoint::base_point();
        assert!(base.is_on_curve(), "Base point not on curve");
        
        // Test manual doubling
        let p2 = base.double();
        println!("\nTesting 2*G via double():");
        check_extended_invariant(&p2, "2*G");
        assert!(p2.is_on_curve(), "2*G not on curve");
        
        let p4 = p2.double();
        assert!(p4.is_on_curve(), "4*G not on curve");
        
        let p8 = p4.double();
        assert!(p8.is_on_curve(), "8*G not on curve");
        
        // Test addition
        let p3 = p2.add(&base);
        println!("Testing 3*G = 2*G + G");
        println!("p3.x bytes: {:02x?}", &p3.x.to_bytes()[..8]);
        println!("p3.y bytes: {:02x?}", &p3.y.to_bytes()[..8]);
        println!("p3.z bytes: {:02x?}", &p3.z.to_bytes()[..8]);
        println!("p3.t bytes: {:02x?}", &p3.t.to_bytes()[..8]);
        check_extended_invariant(&p3, "3*G before is_on_curve check");
        
        // Debug is_on_curve
        let x2 = p3.x.square();
        let y2 = p3.y.square();
        let z2 = p3.z.square();
        let z4 = z2.square();
        let left = y2.mul(&z2).sub(&x2.mul(&z2));
        let right = z4.add(&EdwardsPoint::edwards_d().mul(&x2).mul(&y2));
        println!("is_on_curve check:");
        println!("  left bytes: {:02x?}", &left.to_bytes()[..8]);
        println!("  right bytes: {:02x?}", &right.to_bytes()[..8]);
        println!("  left == right: {}", left == right);
        
        assert!(p3.is_on_curve(), "3*G (2*G + G) not on curve");
        
        // Test with scalar multiplication algorithm
        println!("\nTesting scalar multiplication algorithm:");
        
        // Test with scalar = 3
        let scalar_3 = [3u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result_3 = base.scalar_mul(&scalar_3);
        assert!(result_3.is_on_curve(), "3*G via scalar_mul not on curve");
        
        // Test the extended coordinate invariant
        check_extended_invariant(&base, "base");
        check_extended_invariant(&p2, "2*G");
        check_extended_invariant(&p3, "3*G");
        check_extended_invariant(&result_3, "3*G via scalar_mul");
        
        // Test with larger scalar
        let scalar_255 = [255u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result_255 = base.scalar_mul(&scalar_255);
        println!("\n255*G is on curve: {}", result_255.is_on_curve());
        check_extended_invariant(&result_255, "255*G");
    }
    
    fn check_extended_invariant(point: &EdwardsPoint, name: &str) {
        let tz = point.t.mul(&point.z);
        let xy = point.x.mul(&point.y);
        let equal = tz == xy;
        println!("{}: t*z == x*y: {}", name, equal);
        if !equal {
            println!("  t*z bytes: {:02x?}", &tz.to_bytes()[..8]);
            println!("  x*y bytes: {:02x?}", &xy.to_bytes()[..8]);
        }
    }
}