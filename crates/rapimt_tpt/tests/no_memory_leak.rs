use std::collections::HashSet;

use peak_alloc::PeakAlloc;
use rapimt_core::r#match::MaskedValue;
use rapimt_tpt::{Segmentizer, TernaryPatriciaTree};

#[test]
#[ignore = "test should be run mannually"]
fn test_no_memory_leak() {
    #[global_allocator]
    static PEAK_ALLOC: PeakAlloc = PeakAlloc;

    let mut tpt = TernaryPatriciaTree::<u32, HashSet<u32>>::new(32);

    let mut mvs = vec![];
    for i in 0..u8::MAX {
        let mask = u32::MAX >> i.leading_zeros();
        mvs.push(MaskedValue::store(i as u32, mask, 0, 32));
    }
    let current_mem = PEAK_ALLOC.current_usage_as_kb();
    println!("This program initially uses {} kB of RAM.", current_mem);

    // First round ---------------
    for i in 0..u8::MAX {
        tpt.insert(i as u32, Segmentizer::from(mvs[i as usize]));
    }
    let current_mem = PEAK_ALLOC.current_usage_as_kb();
    println!(
        "first time: after insertion one-by-one: it uses {} kB of RAM.",
        current_mem
    );

    tpt.clear();
    let current_mem = PEAK_ALLOC.current_usage_as_kb();
    println!(
        "first time: after deletion at once: it uses {} kB of RAM.",
        current_mem
    );

    // Second round ---------------
    for i in 0..u8::MAX {
        tpt.insert(i as u32, Segmentizer::from(mvs[i as usize]));
    }
    let current_mem = PEAK_ALLOC.current_usage_as_kb();
    println!(
        "second time: after insertion one-by-one: it uses {} kB of RAM.",
        current_mem
    );

    for i in 0..u8::MAX {
        tpt.delete(&(i as u32), Segmentizer::from(mvs[i as usize]));
    }
    let current_mem = PEAK_ALLOC.current_usage_as_kb();
    println!(
        "second time: after deletion one-by-one: it uses {} kB of RAM.",
        current_mem
    );

    // Third round ---------------
    for i in 0..u8::MAX {
        tpt.insert(i as u32, Segmentizer::from(mvs[i as usize]));
    }
    let current_mem = PEAK_ALLOC.current_usage_as_kb();
    println!(
        "third time: after insertion one-by-one: it uses {} kB of RAM.",
        current_mem
    );

    tpt.clear();
    let current_mem = PEAK_ALLOC.current_usage_as_kb();
    println!(
        "third time: after deletion at once: it uses {} kB of RAM.",
        current_mem
    );

    // Forth round ---------------
    for i in 0..u8::MAX {
        tpt.insert(i as u32, Segmentizer::from(mvs[i as usize]));
    }
    let current_mem = PEAK_ALLOC.current_usage_as_kb();
    println!(
        "forth time: after insertion one-by-one: it uses {} kB of RAM.",
        current_mem
    );

    for i in 0..u8::MAX {
        tpt.delete(&(i as u32), Segmentizer::from(mvs[i as usize]));
    }
    let current_mem = PEAK_ALLOC.current_usage_as_kb();
    println!(
        "forth time: after deletion one-by-one: it uses {} kB of RAM.",
        current_mem
    );
}
