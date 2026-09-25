# metamui-blake3 examples

```bash
cargo run --example basic_usage        # one-shot, incremental, hex, empty input
cargo run --example advanced_features  # keyed hash, MAC, derive_key, XOF
cargo run --example batch_processing   # hash_many and batch::batch_hash
cargo run --example parallel_hashing --features multithreading
```

Every example computes the ordinary BLAKE3 digest through the portable
implementation; none needs a particular CPU.
