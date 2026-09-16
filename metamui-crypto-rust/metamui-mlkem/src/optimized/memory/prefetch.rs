//! Prefetching hints for predictable memory access patterns
//!
//! Provides CPU prefetch instructions and access pattern optimizations
//! specifically designed for ML-KEM polynomial operations, particularly NTT.


/// Prefetch hint types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchHint {
    /// Data will be read soon (T0 - closest to CPU)
    ReadT0,
    /// Data will be read soon (T1 - L2 cache)
    ReadT1,
    /// Data will be read soon (T2 - L3 cache)
    ReadT2,
    /// Data will be written soon (T0)
    WriteT0,
    /// Data will be written soon (T1)
    WriteT1,
    /// Data will be written soon (T2)
    WriteT2,
    /// Non-temporal - bypass cache
    NonTemporal,
}

/// Prefetch distance for different operations
pub struct PrefetchConfig {
    /// Distance ahead for sequential access
    pub sequential_distance: usize,
    /// Distance ahead for strided access
    pub strided_distance: usize,
    /// Distance ahead for NTT butterfly operations
    pub ntt_distance: usize,
    /// Cache level hint
    pub hint: PrefetchHint,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            sequential_distance: 8,
            strided_distance: 4,
            ntt_distance: 16,
            hint: PrefetchHint::ReadT1,
        }
    }
}

/// Prefetch data at the given address
#[inline(always)]
pub fn prefetch<T>(ptr: *const T, hint: PrefetchHint) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::*;
        
        unsafe {
            match hint {
                PrefetchHint::ReadT0 => _mm_prefetch(ptr as *const i8, _MM_HINT_T0),
                PrefetchHint::ReadT1 => _mm_prefetch(ptr as *const i8, _MM_HINT_T1),
                PrefetchHint::ReadT2 => _mm_prefetch(ptr as *const i8, _MM_HINT_T2),
                PrefetchHint::WriteT0 => _mm_prefetch(ptr as *const i8, _MM_HINT_T0),
                PrefetchHint::WriteT1 => _mm_prefetch(ptr as *const i8, _MM_HINT_T1),
                PrefetchHint::WriteT2 => _mm_prefetch(ptr as *const i8, _MM_HINT_T2),
                PrefetchHint::NonTemporal => _mm_prefetch(ptr as *const i8, _MM_HINT_NTA),
            }
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        
        
        unsafe {
            match hint {
                PrefetchHint::ReadT0 | PrefetchHint::ReadT1 => {
                    // PRFM PLDL1KEEP
                    core::arch::asm!("prfm pldl1keep, [{0}]", in(reg) ptr);
                }
                PrefetchHint::ReadT2 => {
                    // PRFM PLDL2KEEP
                    core::arch::asm!("prfm pldl2keep, [{0}]", in(reg) ptr);
                }
                PrefetchHint::WriteT0 | PrefetchHint::WriteT1 => {
                    // PRFM PSTL1KEEP
                    core::arch::asm!("prfm pstl1keep, [{0}]", in(reg) ptr);
                }
                PrefetchHint::WriteT2 => {
                    // PRFM PSTL2KEEP
                    core::arch::asm!("prfm pstl2keep, [{0}]", in(reg) ptr);
                }
                PrefetchHint::NonTemporal => {
                    // PRFM PLDL1STRM
                    core::arch::asm!("prfm pldl1strm, [{0}]", in(reg) ptr);
                }
            }
        }
    }
    
    // For other architectures, prefetch is a no-op
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (ptr, hint);
    }
}

/// Prefetch multiple cache lines
#[inline(always)]
pub fn prefetch_range<T>(ptr: *const T, count: usize, hint: PrefetchHint) {
    const CACHE_LINE_SIZE: usize = 64;
    let element_size = core::mem::size_of::<T>();
    let total_size = count * element_size;
    let cache_lines = (total_size + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE;
    
    for i in 0..cache_lines {
        let addr = unsafe { (ptr as *const u8).add(i * CACHE_LINE_SIZE) };
        prefetch(addr, hint);
    }
}

/// Sequential prefetcher for linear access patterns
pub struct SequentialPrefetcher {
    config: PrefetchConfig,
    current_offset: usize,
}

impl SequentialPrefetcher {
    /// Create new sequential prefetcher
    pub fn new(config: PrefetchConfig) -> Self {
        Self {
            config,
            current_offset: 0,
        }
    }
    
    /// Process next element and prefetch ahead
    #[inline]
    pub fn next<T>(&mut self, base: *const T, index: usize) {
        let prefetch_index = index + self.config.sequential_distance;
        let ptr = unsafe { base.add(prefetch_index) };
        prefetch(ptr, self.config.hint);
        self.current_offset = index;
    }
    
    /// Prefetch initial batch
    #[inline]
    pub fn init<T>(&self, base: *const T) {
        for i in 0..self.config.sequential_distance {
            let ptr = unsafe { base.add(i) };
            prefetch(ptr, self.config.hint);
        }
    }
}

/// Strided prefetcher for non-contiguous access patterns
pub struct StridedPrefetcher {
    config: PrefetchConfig,
    stride: usize,
}

impl StridedPrefetcher {
    /// Create new strided prefetcher
    pub fn new(config: PrefetchConfig, stride: usize) -> Self {
        Self { config, stride }
    }
    
    /// Prefetch next strided element
    #[inline]
    pub fn next<T>(&self, base: *const T, index: usize) {
        let prefetch_index = index + self.config.strided_distance * self.stride;
        let ptr = unsafe { base.add(prefetch_index) };
        prefetch(ptr, self.config.hint);
    }
    
    /// Prefetch initial batch
    #[inline]
    pub fn init<T>(&self, base: *const T, start_index: usize) {
        for i in 0..self.config.strided_distance {
            let index = start_index + i * self.stride;
            let ptr = unsafe { base.add(index) };
            prefetch(ptr, self.config.hint);
        }
    }
}

/// NTT-specific prefetcher for butterfly access patterns
pub struct NTTPrefetcher {
    config: PrefetchConfig,
    n: usize,
    log_n: usize,
}

impl NTTPrefetcher {
    /// Create new NTT prefetcher
    pub fn new(n: usize) -> Self {
        let log_n = n.trailing_zeros() as usize;
        Self {
            config: PrefetchConfig {
                ntt_distance: 16,
                hint: PrefetchHint::ReadT1,
                ..Default::default()
            },
            n,
            log_n,
        }
    }
    
    /// Prefetch for Cooley-Tukey butterfly pattern
    #[inline]
    pub fn butterfly<T>(&self, data: *const T, stage: usize, index: usize) {
        let m = 1 << (self.log_n - stage);
        let half_m = m >> 1;
        
        // Prefetch butterfly pair ahead
        let prefetch_offset = self.config.ntt_distance;
        let i = index + prefetch_offset;
        
        if i < self.n {
            let k = i & (half_m - 1);
            let j = ((i - k) << 1) + k;
            
            let ptr1 = unsafe { data.add(j) };
            let ptr2 = unsafe { data.add(j + m) };
            
            prefetch(ptr1, PrefetchHint::ReadT0);
            prefetch(ptr2, PrefetchHint::ReadT0);
        }
    }
    
    /// Prefetch for bit-reversal permutation
    #[inline]
    pub fn bit_reversal<T>(&self, data: *const T, index: usize) {
        let prefetch_index = index + self.config.ntt_distance;
        
        if prefetch_index < self.n {
            let rev = self.bit_reverse(prefetch_index);
            let ptr = unsafe { data.add(rev) };
            prefetch(ptr, PrefetchHint::ReadT1);
        }
    }
    
    /// Bit reverse index
    #[inline]
    fn bit_reverse(&self, x: usize) -> usize {
        let mut r = 0;
        let mut x = x;
        for _ in 0..self.log_n {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
        r
    }
}

/// Matrix operation prefetcher
pub struct MatrixPrefetcher {
    config: PrefetchConfig,
    rows: usize,
    cols: usize,
}

impl MatrixPrefetcher {
    /// Create new matrix prefetcher
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            config: Default::default(),
            rows,
            cols,
        }
    }
    
    /// Prefetch for row-major traversal
    #[inline]
    pub fn row_major<T>(&self, matrix: *const T, row: usize, col: usize) {
        let next_col = col + self.config.sequential_distance;
        if next_col < self.cols {
            let index = row * self.cols + next_col;
            let ptr = unsafe { matrix.add(index) };
            prefetch(ptr, self.config.hint);
        } else if row + 1 < self.rows {
            // Prefetch start of next row
            let index = (row + 1) * self.cols;
            let ptr = unsafe { matrix.add(index) };
            prefetch(ptr, self.config.hint);
        }
    }
    
    /// Prefetch for column-major traversal
    #[inline]
    pub fn col_major<T>(&self, matrix: *const T, row: usize, col: usize) {
        let next_row = row + self.config.strided_distance;
        if next_row < self.rows {
            let index = next_row * self.cols + col;
            let ptr = unsafe { matrix.add(index) };
            prefetch(ptr, self.config.hint);
        } else if col + 1 < self.cols {
            // Prefetch start of next column
            let index = col + 1;
            let ptr = unsafe { matrix.add(index) };
            prefetch(ptr, self.config.hint);
        }
    }
    
    /// Prefetch for tiled/blocked access
    #[inline]
    pub fn tiled<T>(&self, matrix: *const T, tile_row: usize, tile_col: usize, 
                    tile_size: usize, inner_row: usize, inner_col: usize) {
        // Prefetch within current tile
        let row = tile_row * tile_size + inner_row;
        let col = tile_col * tile_size + inner_col;
        
        if row < self.rows && col < self.cols {
            let next_index = (row * self.cols + col) + self.config.sequential_distance;
            if next_index < self.rows * self.cols {
                let ptr = unsafe { matrix.add(next_index) };
                prefetch(ptr, self.config.hint);
            }
        }
        
        // Prefetch next tile boundary
        if inner_row == tile_size - 1 && inner_col == tile_size - 1 {
            let next_tile_row = tile_row + 1;
            let next_tile_col = tile_col + 1;
            
            if next_tile_row < (self.rows + tile_size - 1) / tile_size {
                let index = next_tile_row * tile_size * self.cols + tile_col * tile_size;
                let ptr = unsafe { matrix.add(index) };
                prefetch(ptr, PrefetchHint::ReadT2);
            }
            
            if next_tile_col < (self.cols + tile_size - 1) / tile_size {
                let index = tile_row * tile_size * self.cols + next_tile_col * tile_size;
                let ptr = unsafe { matrix.add(index) };
                prefetch(ptr, PrefetchHint::ReadT2);
            }
        }
    }
}

/// Adaptive prefetcher that adjusts based on access patterns
pub struct AdaptivePrefetcher {
    sequential: SequentialPrefetcher,
    strided: Option<StridedPrefetcher>,
    last_indices: Vec<usize>,
    pattern_detected: AccessPattern,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessPattern {
    Unknown,
    Sequential,
    Strided(usize),
    Random,
}

impl AdaptivePrefetcher {
    /// Create new adaptive prefetcher
    pub fn new() -> Self {
        Self {
            sequential: SequentialPrefetcher::new(Default::default()),
            strided: None,
            last_indices: Vec::with_capacity(8),
            pattern_detected: AccessPattern::Unknown,
        }
    }
    
    /// Process access and adapt prefetch strategy
    #[inline]
    pub fn access<T>(&mut self, base: *const T, index: usize) {
        // Detect pattern
        if self.last_indices.len() >= 3 {
            self.detect_pattern();
        }
        
        // Apply appropriate prefetch strategy
        match self.pattern_detected {
            AccessPattern::Sequential => {
                self.sequential.next(base, index);
            }
            AccessPattern::Strided(stride) => {
                if let Some(ref mut strided) = self.strided {
                    strided.next(base, index);
                } else {
                    let config = PrefetchConfig::default();
                    let strided = StridedPrefetcher::new(config, stride);
                    strided.next(base, index);
                    self.strided = Some(strided);
                }
            }
            AccessPattern::Random | AccessPattern::Unknown => {
                // Random access - prefetch next cache line
                let ptr = unsafe { base.add(index + 1) };
                prefetch(ptr, PrefetchHint::ReadT2);
            }
        }
        
        // Record access
        self.last_indices.push(index);
        if self.last_indices.len() > 8 {
            self.last_indices.remove(0);
        }
    }
    
    /// Detect access pattern from history
    fn detect_pattern(&mut self) {
        if self.last_indices.len() < 3 {
            return;
        }
        
        // Check for sequential pattern
        let mut sequential = true;
        for i in 1..self.last_indices.len() {
            if self.last_indices[i] != self.last_indices[i-1] + 1 {
                sequential = false;
                break;
            }
        }
        
        if sequential {
            self.pattern_detected = AccessPattern::Sequential;
            return;
        }
        
        // Check for strided pattern
        if self.last_indices.len() >= 3 {
            let stride1 = self.last_indices[1].wrapping_sub(self.last_indices[0]);
            let stride2 = self.last_indices[2].wrapping_sub(self.last_indices[1]);
            
            if stride1 == stride2 && stride1 > 0 {
                let mut consistent = true;
                for i in 3..self.last_indices.len() {
                    let stride = self.last_indices[i].wrapping_sub(self.last_indices[i-1]);
                    if stride != stride1 {
                        consistent = false;
                        break;
                    }
                }
                
                if consistent {
                    self.pattern_detected = AccessPattern::Strided(stride1);
                    return;
                }
            }
        }
        
        // Otherwise, consider it random
        self.pattern_detected = AccessPattern::Random;
    }
}

/// Helper functions for common prefetch patterns
pub mod helpers {
    use super::*;
    
    /// Prefetch array for sequential read
    #[inline]
    pub fn prefetch_sequential_read<T>(data: &[T], start: usize, distance: usize) {
        let end = (start + distance).min(data.len());
        for i in start..end {
            prefetch(&data[i] as *const T, PrefetchHint::ReadT1);
        }
    }
    
    /// Prefetch array for sequential write
    #[inline]
    pub fn prefetch_sequential_write<T>(data: &mut [T], start: usize, distance: usize) {
        let end = (start + distance).min(data.len());
        for i in start..end {
            prefetch(&data[i] as *const T, PrefetchHint::WriteT1);
        }
    }
    
    /// Prefetch for polynomial multiplication
    #[inline]
    pub fn prefetch_poly_mul(a: &[i16], b: &[i16], result: &mut [i16], index: usize) {
        const DISTANCE: usize = 8;
        
        if index + DISTANCE < a.len() {
            prefetch(&a[index + DISTANCE] as *const i16, PrefetchHint::ReadT0);
            prefetch(&b[index + DISTANCE] as *const i16, PrefetchHint::ReadT0);
            prefetch(&result[index + DISTANCE] as *const i16, PrefetchHint::WriteT0);
        }
    }
    
    /// Prefetch for NTT butterfly operation
    #[inline]
    pub fn prefetch_ntt_butterfly(data: &mut [i16], j: usize, k: usize, distance: usize) {
        if j + distance < data.len() && k + distance < data.len() {
            prefetch(&data[j + distance] as *const i16, PrefetchHint::ReadT0);
            prefetch(&data[k + distance] as *const i16, PrefetchHint::ReadT0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sequential_prefetcher() {
        let data = vec![0i32; 1024];
        let mut prefetcher = SequentialPrefetcher::new(Default::default());
        
        prefetcher.init(data.as_ptr());
        
        for i in 0..100 {
            prefetcher.next(data.as_ptr(), i);
        }
    }
    
    #[test]
    fn test_strided_prefetcher() {
        let data = vec![0i32; 1024];
        let prefetcher = StridedPrefetcher::new(Default::default(), 8);
        
        prefetcher.init(data.as_ptr(), 0);
        
        for i in (0..100).step_by(8) {
            prefetcher.next(data.as_ptr(), i);
        }
    }
    
    #[test]
    fn test_ntt_prefetcher() {
        let data = vec![0i16; 256];
        let prefetcher = NTTPrefetcher::new(256);
        
        // Test butterfly prefetch
        for stage in 0..8 {
            for i in 0..256 {
                prefetcher.butterfly(data.as_ptr(), stage, i);
            }
        }
        
        // Test bit-reversal prefetch
        for i in 0..256 {
            prefetcher.bit_reversal(data.as_ptr(), i);
        }
    }
    
    #[test]
    fn test_matrix_prefetcher() {
        let rows = 64;
        let cols = 64;
        let matrix = vec![0i32; rows * cols];
        let prefetcher = MatrixPrefetcher::new(rows, cols);
        
        // Test row-major
        for i in 0..rows {
            for j in 0..cols {
                prefetcher.row_major(matrix.as_ptr(), i, j);
            }
        }
        
        // Test column-major
        for j in 0..cols {
            for i in 0..rows {
                prefetcher.col_major(matrix.as_ptr(), i, j);
            }
        }
    }
    
    #[test]
    fn test_adaptive_prefetcher() {
        let data = vec![0i32; 1024];
        let mut prefetcher = AdaptivePrefetcher::new();
        
        // Sequential access
        for i in 0..10 {
            prefetcher.access(data.as_ptr(), i);
        }
        assert_eq!(prefetcher.pattern_detected, AccessPattern::Sequential);
        
        // Strided access
        let mut prefetcher = AdaptivePrefetcher::new();
        for i in (0..50).step_by(5) {
            prefetcher.access(data.as_ptr(), i);
        }
        assert_eq!(prefetcher.pattern_detected, AccessPattern::Strided(5));
    }
}