//! Direct SMT CLZ/CLS formula benchmark for issue #112.

use criterion::{Criterion, criterion_group, criterion_main};
use s11::ir::{Instruction, Register};
use s11::semantics::{
    EquivalenceConfig, EquivalenceResult, RegisterSet, check_equivalence_with_config_metrics,
};
use std::hint::black_box;
use std::time::Duration;

struct SmtClzCase {
    name: &'static str,
    sequence: Vec<Instruction>,
    live_out: RegisterSet<Register>,
}

fn smt_clz_cases() -> Vec<SmtClzCase> {
    vec![
        SmtClzCase {
            name: "one_clz",
            sequence: vec![Instruction::Clz {
                rd: Register::X0,
                rn: Register::X1,
            }],
            live_out: RegisterSet::from_registers(vec![Register::X0]),
        },
        SmtClzCase {
            name: "four_clz",
            sequence: vec![
                Instruction::Clz {
                    rd: Register::X0,
                    rn: Register::X4,
                },
                Instruction::Clz {
                    rd: Register::X1,
                    rn: Register::X5,
                },
                Instruction::Clz {
                    rd: Register::X2,
                    rn: Register::X6,
                },
                Instruction::Clz {
                    rd: Register::X3,
                    rn: Register::X7,
                },
            ],
            live_out: RegisterSet::from_registers(vec![
                Register::X0,
                Register::X1,
                Register::X2,
                Register::X3,
            ]),
        },
        SmtClzCase {
            name: "one_cls",
            sequence: vec![Instruction::Cls {
                rd: Register::X0,
                rn: Register::X1,
            }],
            live_out: RegisterSet::from_registers(vec![Register::X0]),
        },
        SmtClzCase {
            name: "four_cls",
            sequence: vec![
                Instruction::Cls {
                    rd: Register::X0,
                    rn: Register::X4,
                },
                Instruction::Cls {
                    rd: Register::X1,
                    rn: Register::X5,
                },
                Instruction::Cls {
                    rd: Register::X2,
                    rn: Register::X6,
                },
                Instruction::Cls {
                    rd: Register::X3,
                    rn: Register::X7,
                },
            ],
            live_out: RegisterSet::from_registers(vec![
                Register::X0,
                Register::X1,
                Register::X2,
                Register::X3,
            ]),
        },
    ]
}

fn smt_clz(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_clz");
    group.sample_size(10);

    for case in smt_clz_cases() {
        group.bench_function(case.name, |b| {
            b.iter(|| {
                let config = EquivalenceConfig::with_live_out(case.live_out.clone())
                    .random_tests(0)
                    .timeout(Duration::from_secs(30));
                let (result, metrics) = check_equivalence_with_config_metrics(
                    black_box(&case.sequence),
                    black_box(&case.sequence),
                    &config,
                );
                assert_eq!(result, EquivalenceResult::Equivalent);
                black_box((metrics.smt_elapsed, metrics.smt_formula_bytes));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, smt_clz);
criterion_main!(benches);
