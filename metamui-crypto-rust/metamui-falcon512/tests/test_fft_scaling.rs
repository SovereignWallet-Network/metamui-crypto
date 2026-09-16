use metamui_falcon512::fft_hybrid::{HybridFFT, FFTMode};
use metamui_falcon512::poly::PolyF64;

#[test]
fn test_fft_scaling_diagnostic() {
    println!("Testing FFT scaling issue...\n");
    
    // Simple test case
    let poly = PolyF64::new(vec![1.0, 2.0, 3.0, 4.0]);
    println!("Original: {:?}", poly.coeffs);
    
    // Test native mode (should work)
    println!("\n=== Native Mode ===");
    let fft_native = HybridFFT::new(FFTMode::Native);
    let fft_result = fft_native.forward(&poly);
    println!("After forward FFT:");
    for (i, c) in fft_result.iter().enumerate() {
        let (re, im) = c.to_native();
        println!("  [{i}] = {re:.4} + {im:.4}i");
    }
    
    let recovered = fft_native.inverse(&fft_result);
    println!("Recovered: {:?}", recovered.coeffs);
    for i in 0..4 {
        let error = (recovered.coeffs[i] - poly.coeffs[i]).abs();
        println!("  Error[{i}]: {error:.10}");
    }
    
    // Test emulated mode (has issues)
    println!("\n=== Emulated Mode ===");
    let fft_emulated = HybridFFT::new(FFTMode::Emulated);
    let fft_result_emu = fft_emulated.forward(&poly);
    println!("After forward FFT:");
    for (i, c) in fft_result_emu.iter().enumerate() {
        let (re, im) = c.to_native();
        println!("  [{i}] = {re:.4} + {im:.4}i");
    }
    
    let recovered_emu = fft_emulated.inverse(&fft_result_emu);
    println!("Recovered: {:?}", recovered_emu.coeffs);
    for i in 0..4 {
        let error = (recovered_emu.coeffs[i] - poly.coeffs[i]).abs();
        println!("  Error[{i}]: {error:.10}");
    }
    
    // Compare FFT results
    println!("\n=== Comparing FFT results ===");
    for i in 0..4 {
        let (re_native, im_native) = fft_result[i].to_native();
        let (re_emu, im_emu) = fft_result_emu[i].to_native();
        println!("FFT[{i}]:");
        println!("  Native:   {re_native:.6} + {im_native:.6}i");
        println!("  Emulated: {re_emu:.6} + {im_emu:.6}i");
        println!("  Diff:     {:.6} + {:.6}i", 
                 (re_native - re_emu).abs(), 
                 (im_native - im_emu).abs());
    }
}