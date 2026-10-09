//! A whole dump in a process running jemalloc with the sampler on.

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

vlsync_heapprof::malloc_conf!("background_thread:false");

#[inline(never)]
fn hold_some_blocks() -> Vec<Vec<u8>> {
    (0..256).map(|i| vec![i as u8; 256 << 10]).collect()
}

#[test]
fn dumps_the_heap_in_use_with_its_allocating_function() {
    let s = vlsync_heapprof::status();
    assert!(s.enabled && s.active, "{s:?}");
    assert_eq!(s.sample_bytes, 512 << 10);
    let held = std::hint::black_box(hold_some_blocks());
    let gz = vlsync_heapprof::dump_pprof().unwrap();
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut raw).unwrap();
    let has = |s: &str| raw.windows(s.len()).any(|w| w == s.as_bytes());
    assert!(has("inuse_space"));
    assert!(has("hold_some_blocks"), "the allocating function is named");
    assert!(!has("prof_backtrace"), "jemalloc's own frames are cut");
    drop(held);
    // a second dump reuses the symbols
    vlsync_heapprof::dump_pprof().unwrap();
    vlsync_heapprof::set_active(false).unwrap();
    assert!(matches!(vlsync_heapprof::dump_pprof(), Err(vlsync_heapprof::Error::Inactive)));
}
