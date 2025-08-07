use criterion::{criterion_group, criterion_main, Criterion};
use ipc_channel::ipc;
use rand::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
enum TestSmall {
    Msg0,
    Msg1,
    Msg2(u32, u32),
    Msg3(u32, u32, u32),
    Msg4(String),
    Msg5,
    Msg6,
}

trait NewFromRandom {
    fn new(rng: &mut ThreadRng) -> Self;
}

impl NewFromRandom for TestSmall {
    fn new(rng: &mut ThreadRng) -> Self {
        match rng.random_range(0..=6) {
            0 => Self::Msg0,
            1 => Self::Msg1,
            2 => Self::Msg2(23, 42),
            3 => Self::Msg3(23, 42, 243),
            4 => Self::Msg4(String::from("This is a test string of medium size")),
            5 => Self::Msg5,
            6 => Self::Msg6,
            _ => Self::Msg6,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
enum TestMedium {
    Msg0(u32),
    Msg1(u32),
    Msg2(u32),
    Msg3(u32),
    Msg4(u32),
    Msg5(u32),
    Msg6(u32),
    Msg7(u32),
    Msg8(u32),
    Msg9(u32),
    Msg10(u32),
    Msg11(u32),
    Msg12(u32),
    Msg13(u32),
    Msg14(u32),
    Msg15(u32),
    Msg16(u32),
    Msg17(u32),
    Msg18(u32),
    Msg19(u32),
    Msg20(u32),
    Msg21(u32),
    Msg22(u32),
    Msg23(u32),
    Msg24(u32),
    Msg25(u32),
    Msg26(u32),
}

impl NewFromRandom for TestMedium {
    fn new(rng: &mut ThreadRng) -> Self {
        match rng.random_range(0..=26) {
            0 => Self::Msg0(42),
            1 => Self::Msg1(42),
            2 => Self::Msg2(42),
            3 => Self::Msg3(42),
            4 => Self::Msg4(42),
            5 => Self::Msg5(42),
            6 => Self::Msg6(42),
            7 => Self::Msg7(42),
            8 => Self::Msg8(42),
            9 => Self::Msg9(42),
            10 => Self::Msg10(42),
            11 => Self::Msg11(42),
            12 => Self::Msg12(42),
            13 => Self::Msg13(42),
            14 => Self::Msg14(42),
            15 => Self::Msg15(42),
            16 => Self::Msg16(42),
            17 => Self::Msg17(42),
            18 => Self::Msg18(42),
            19 => Self::Msg19(42),
            20 => Self::Msg20(42),
            21 => Self::Msg21(42),
            22 => Self::Msg22(42),
            23 => Self::Msg23(42),
            24 => Self::Msg24(42),
            25 => Self::Msg25(42),
            26 => Self::Msg26(42),
            _ => Self::Msg6(42),
        }
    }
}

#[derive(Serialize, Deserialize)]
enum TestFractured {
    Msg0,
    Msg1(Vec<usize>),
    Msg2(
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    ),
    Msg3(usize),
    Msg4(usize, usize, usize),
}

impl NewFromRandom for TestFractured {
    fn new(rng: &mut ThreadRng) -> Self {
        match rng.random_range(0..=4) {
            0 => Self::Msg0,
            1 => Self::Msg1(vec![1, 2, 3]),
            2 => Self::Msg2(1, 2, 3, 4, 5, 6, 7, 8, 9, 10),
            3 => Self::Msg3(1),
            4 => Self::Msg4(1, 2, 3),
            _ => Self::Msg3(1),
        }
    }
}

#[derive(Serialize, Deserialize)]
enum TestNested {
    Msg0,
    Msg1(TestSmall),
    Msg2(TestMedium),
    Msg3(TestFractured),
    Msg4(usize),
}

impl NewFromRandom for TestNested {
    fn new(rng: &mut ThreadRng) -> Self {
        match rng.random_range(0..=5) {
            0 => Self::Msg0,
            1 => Self::Msg1(TestSmall::Msg6),
            2 => Self::Msg2(TestMedium::Msg20(2)),
            3 => Self::Msg3(TestFractured::Msg3(0)),
            4 => Self::Msg4(2),
            _ => Self::Msg3(TestFractured::Msg0),
        }
    }
}

fn transfer_enum<T>(criterion: &mut Criterion)
where
    T: NewFromRandom,
    T: for<'de> Deserialize<'de>,
    T: Serialize,
{
    criterion.bench_function("transfer_simple_struct", |bencher| {
        let (tx, rx) = ipc::channel().unwrap();
        let mut rng = rand::rng();

        bencher.iter_batched(
            || T::new(&mut rng),
            |s| {
                tx.send(s).unwrap();
                rx.recv().unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

// TestSmall is a small enum
// TestMedium is a medium size enum
// TestFractured is an enum with varying sizes of inners
// TestNested nests the enums

criterion_group!(
    benches,
    transfer_enum<TestSmall>,
    transfer_enum<TestMedium>,
    transfer_enum<TestFractured>,
    transfer_enum<TestNested>,
);

criterion_main!(benches);
