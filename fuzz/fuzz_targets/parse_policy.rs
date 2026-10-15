#![no_main]

use ai_sandbox::parse_policy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    if let Ok(policy) = parse_policy(&input) {
        let command = vec![input.chars().take(32).collect::<String>()];
        let _ = policy.check(&command);
    }
});