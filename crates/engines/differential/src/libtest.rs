//! Parsing of libtest's human output (`test name ... ok|FAILED|ignored`).

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestStatus {
    Ignored,
    Passed,
    Failed,
}

/// Test name -> status. When the same name appears in several test binaries
/// the worst status wins (a name "passes" only if every instance passed).
pub fn parse_test_output(stdout: &[u8]) -> BTreeMap<String, TestStatus> {
    let mut out = BTreeMap::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let Some(rest) = line.strip_prefix("test ") else {
            continue;
        };
        let Some((name, result)) = rest.split_once(" ... ") else {
            continue;
        };
        let status = match result.split_whitespace().next() {
            Some("ok") => TestStatus::Passed,
            Some("FAILED") => TestStatus::Failed,
            Some("ignored" | "ignored,") => TestStatus::Ignored,
            _ => continue,
        };
        // `#[should_panic]` tests print `name - should panic`.
        let name = name.split(" - ").next().unwrap_or(name).trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            continue;
        }
        let e = out.entry(name.to_string()).or_insert(status);
        *e = (*e).max(status);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_libtest_lines() {
        let out = b"\nrunning 4 tests\n\
test tests::a ... ok\n\
test tests::b ... FAILED\n\
test tests::c ... ignored, slow\n\
test tests::d - should panic ... ok\n\
test result: FAILED. 1 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\
test tests::a ... FAILED\n";
        let m = parse_test_output(out);
        assert_eq!(m.len(), 4);
        assert_eq!(m["tests::d"], TestStatus::Passed);
        // `tests::a` failed in a second binary.
        assert_eq!(m["tests::a"], TestStatus::Failed);
        assert_eq!(m["tests::b"], TestStatus::Failed);
        assert_eq!(m["tests::c"], TestStatus::Ignored);
    }
}
