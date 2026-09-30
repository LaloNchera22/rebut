//! Parsing `cargo kani` output.
//!
//! A Kani `FAILED` result is *not* a finding by itself: it is a claim by a
//! model checker about a model of the program. It becomes a finding only once
//! the counterexample it prints (`--concrete-playback=print`) has been
//! replayed against the real binary inside the fabric (ADR-6).

use crate::codegen::ArgType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KaniOutcome {
    /// `VERIFICATION:- SUCCESSFUL`: the property holds for all inputs within
    /// the unwinding bounds.
    Verified,
    /// `VERIFICATION:- FAILED`.
    Failed {
        /// Descriptions of the checks with `Status: FAILURE`.
        failed_checks: Vec<String>,
        /// Values of the `kani::any()` calls, in call order, if Kani printed
        /// a concrete playback test.
        counterexample: Option<Vec<Vec<u8>>>,
    },
    /// No verdict line (compile error, timeout, unsupported feature...).
    Unknown,
}

pub fn parse_kani_output(out: &str) -> KaniOutcome {
    let verdict = out.lines().rev().find_map(|l| {
        let l = l.trim();
        if l.starts_with("VERIFICATION:- SUCCESSFUL") {
            Some(true)
        } else if l.starts_with("VERIFICATION:- FAILED") {
            Some(false)
        } else {
            None
        }
    });
    match verdict {
        None => KaniOutcome::Unknown,
        Some(true) => KaniOutcome::Verified,
        Some(false) => KaniOutcome::Failed {
            failed_checks: failed_checks(out),
            counterexample: concrete_values(out),
        },
    }
}

/// Collect `Check N:` blocks whose status is `FAILURE`.
fn failed_checks(out: &str) -> Vec<String> {
    let mut failed = Vec::new();
    let mut current: Option<(String, bool, Option<String>)> = None;
    let flush = |c: Option<(String, bool, Option<String>)>, failed: &mut Vec<String>| {
        if let Some((name, true, desc)) = c {
            failed.push(desc.unwrap_or(name));
        }
    };
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Check ") {
            flush(current.take(), &mut failed);
            let name = rest.split_once(": ").map(|x| x.1).unwrap_or(rest);
            current = Some((name.to_string(), false, None));
        } else if let Some(c) = current.as_mut() {
            if let Some(s) = t.strip_prefix("- Status:") {
                c.1 = s.trim() == "FAILURE";
            } else if let Some(d) = t.strip_prefix("- Description:") {
                c.2 = Some(d.trim().trim_matches('"').to_string());
            } else if t.is_empty() || t.starts_with("SUMMARY") {
                flush(current.take(), &mut failed);
            }
        }
    }
    flush(current, &mut failed);
    failed
}

/// Extract the `concrete_vals` of the first printed playback test:
///
/// ```text
/// let concrete_vals: Vec<Vec<u8>> = vec![
///     // 4294967295
///     vec![255, 255, 255, 255],
/// ];
/// ```
fn concrete_values(out: &str) -> Option<Vec<Vec<u8>>> {
    let start = out.find("concrete_vals")?;
    let body = &out[start..];
    let body = &body[body.find("vec![")? + "vec![".len()..];
    let mut vals = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with("];") {
            return Some(vals);
        }
        if t.starts_with("//") || t.is_empty() {
            continue;
        }
        let inner = t
            .strip_prefix("vec![")?
            .trim_end_matches(',')
            .strip_suffix(']')?;
        let bytes = inner
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u8>().ok())
            .collect::<Option<Vec<u8>>>()?;
        vals.push(bytes);
    }
    None
}

/// Check that a counterexample has one value of the right width per
/// argument, so the replay harness can decode it.
pub fn check_shape(values: &[Vec<u8>], args: &[ArgType]) -> Result<(), String> {
    if values.len() != args.len() {
        return Err(format!(
            "counterexample has {} values for {} arguments",
            values.len(),
            args.len()
        ));
    }
    for (i, (v, a)) in values.iter().zip(args).enumerate() {
        if v.len() != a.scalar.width() {
            return Err(format!(
                "value {i} has {} bytes, `{}` needs {}",
                v.len(),
                a.scalar.name(),
                a.scalar.width()
            ));
        }
    }
    Ok(())
}

/// Real-shaped `cargo kani --concrete-playback=print` output for a failed proof.
#[cfg(test)]
pub(crate) const FAILED_FIXTURE: &str = r#"Kani Rust Verifier 0.56.0 (cargo plugin)
Checking harness verifier_proof_math_clamp_0...
CBMC 6.3.1 (cbmc-6.3.1)
Runtime Symex: 0.0123s

RESULTS:
Check 1: mylib::math::clamp.arithmetic_overflow.1
	 - Status: SUCCESS
	 - Description: "attempt to subtract with overflow"
	 - Location: src/math.rs:4:12 in function mylib::math::clamp

Check 2: verifier_proof_math_clamp_0.assertion.1
	 - Status: FAILURE
	 - Description: "verifier-formal invariant: ret >= a1 && ret <= a2"
	 - Location: src/lib.rs:31:5 in function verifier_proof_math_clamp_0


SUMMARY:
 ** 1 of 2 failed
Failed Checks: verifier-formal invariant: ret >= a1 && ret <= a2
 File: "src/lib.rs", line 31, in verifier_proof_math_clamp_0

VERIFICATION:- FAILED
Concrete playback unit test for `verifier_proof_math_clamp_0`:
```
/// Test generated for harness `verifier_proof_math_clamp_0`
///
/// Check for `assertion`: "verifier-formal invariant: ret >= a1 && ret <= a2"

#[test]
fn kani_concrete_playback_verifier_proof_math_clamp_0_14615086421508420155() {
    let concrete_vals: Vec<Vec<u8>> = vec![
        // -2147483648
        vec![0, 0, 0, 128],
        // 0
        vec![0, 0, 0, 0],
        // 10
        vec![10, 0, 0, 0],
    ];
    kani::concrete_playback_run(concrete_vals, verifier_proof_math_clamp_0);
}
```
INFO: To automatically add the concrete playback unit test `kani_concrete_playback_verifier_proof_math_clamp_0_14615086421508420155` to the src code, run it with `--concrete-playback=inplace`.
Verification Time: 0.41s

Summary:
Verification failed for - verifier_proof_math_clamp_0
Complete - 0 successfully verified harnesses, 1 failures, 1 total.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    use super::FAILED_FIXTURE as FAILED;

    #[test]
    fn parses_failure_with_counterexample() {
        match parse_kani_output(FAILED) {
            KaniOutcome::Failed {
                failed_checks,
                counterexample,
            } => {
                assert_eq!(
                    failed_checks,
                    vec!["verifier-formal invariant: ret >= a1 && ret <= a2".to_string()]
                );
                assert_eq!(
                    counterexample.unwrap(),
                    vec![vec![0, 0, 0, 128], vec![0, 0, 0, 0], vec![10, 0, 0, 0]]
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_success_and_unknown() {
        let ok = "RESULTS:\nCheck 1: x.assertion.1\n\t - Status: SUCCESS\n\nSUMMARY:\n ** 0 of 1 failed\n\nVERIFICATION:- SUCCESSFUL\nVerification Time: 0.1s\n";
        assert_eq!(parse_kani_output(ok), KaniOutcome::Verified);
        assert_eq!(
            parse_kani_output("error[E0425]: cannot find function `clamp`"),
            KaniOutcome::Unknown
        );
    }

    #[test]
    fn failure_without_playback_has_no_counterexample() {
        let out = FAILED.split("Concrete playback").next().unwrap();
        assert!(matches!(
            parse_kani_output(out),
            KaniOutcome::Failed {
                counterexample: None,
                ..
            }
        ));
    }

    #[test]
    fn shape_check() {
        let args = [
            ArgType::parse("i32").unwrap(),
            ArgType::parse("&bool").unwrap(),
        ];
        assert!(check_shape(&[vec![0; 4], vec![1]], &args).is_ok());
        assert!(check_shape(&[vec![0; 4]], &args).is_err());
        assert!(check_shape(&[vec![0; 8], vec![1]], &args).is_err());
    }
}
