#![feature(test)]

extern crate crossbeam;
extern crate ipc_channel;
extern crate test;

use ipc_channel::platform;

use std::sync::{mpsc, Mutex};

/// Allows doing multiple inner iterations per bench.iter() run.
///
/// This is mostly to amortise the overhead of spawning a thread in the benchmark
/// when sending larger messages (that might be fragmented).
///
/// Note that you need to compensate the displayed results
/// for the proportionally longer runs yourself,
/// as the benchmark framework doesn't know about the inner iterations...
const ITERATIONS: usize = 1;

#[bench]
fn create_channel(b: &mut test::Bencher) {
    b.iter(|| {
        for _ in 0..ITERATIONS {
            platform::channel().unwrap();
        }
    });
}

fn bench_size(b: &mut test::Bencher, size: usize) {
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let (tx, rx) = platform::channel().unwrap();

    let (wait_tx, wait_rx) = mpsc::channel();
    let wait_rx = Mutex::new(wait_rx);

    if size > platform::OsIpcSender::get_max_fragment_size() {
        b.iter(|| {
            crossbeam::scope(|scope| {
                let tx = tx.clone();
                scope.spawn(|| {
                    let wait_rx = wait_rx.lock().unwrap();
                    let tx = tx;
                    for _ in 0..ITERATIONS {
                        tx.send(&data, vec![], vec![]).unwrap();
                        if ITERATIONS > 1 {
                            // Prevent beginning of the next send
                            // from overlapping with receive of last fragment,
                            // as otherwise results of runs with a large tail fragment
                            // are significantly skewed.
                            wait_rx.recv().unwrap();
                        }
                    }
                });
                for _ in 0..ITERATIONS {
                    rx.recv().unwrap();
                    if ITERATIONS > 1 {
                        wait_tx.send(()).unwrap();
                    }
                }
                // For reasons mysterious to me,
                // not returning a value *from every branch*
                // adds some 100 ns or so of overhead to all results --
                // which is quite significant for very short tests...
                0
            })
        });
    } else {
        b.iter(|| {
            for _ in 0..ITERATIONS {
                tx.send(&data, vec![], vec![]).unwrap();
                rx.recv().unwrap();
            }
            0
        });
    }
}

#[bench]
fn size_00_1(b: &mut test::Bencher) {
    bench_size(b, 1);
}
#[bench]
fn size_01_2(b: &mut test::Bencher) {
    bench_size(b, 2);
}
#[bench]
fn size_02_4(b: &mut test::Bencher) {
    bench_size(b, 4);
}
#[bench]
fn size_03_8(b: &mut test::Bencher) {
    bench_size(b, 8);
}
#[bench]
fn size_04_16(b: &mut test::Bencher) {
    bench_size(b, 16);
}
#[bench]
fn size_05_32(b: &mut test::Bencher) {
    bench_size(b, 32);
}
#[bench]
fn size_06_64(b: &mut test::Bencher) {
    bench_size(b, 64);
}
#[bench]
fn size_07_128(b: &mut test::Bencher) {
    bench_size(b, 128);
}
#[bench]
fn size_08_256(b: &mut test::Bencher) {
    bench_size(b, 256);
}
#[bench]
fn size_09_512(b: &mut test::Bencher) {
    bench_size(b, 512);
}
#[bench]
fn size_10_1k(b: &mut test::Bencher) {
    bench_size(b, 1 * 1024);
}
#[bench]
fn size_11_2k(b: &mut test::Bencher) {
    bench_size(b, 2 * 1024);
}
#[bench]
fn size_12_4k(b: &mut test::Bencher) {
    bench_size(b, 4 * 1024);
}
#[bench]
fn size_13_8k(b: &mut test::Bencher) {
    bench_size(b, 8 * 1024);
}
#[bench]
fn size_14_16k(b: &mut test::Bencher) {
    bench_size(b, 16 * 1024);
}
#[bench]
fn size_15_32k(b: &mut test::Bencher) {
    bench_size(b, 32 * 1024);
}
#[bench]
fn size_16_64k(b: &mut test::Bencher) {
    bench_size(b, 64 * 1024);
}
#[bench]
fn size_17_128k(b: &mut test::Bencher) {
    bench_size(b, 128 * 1024);
}
#[bench]
fn size_18_256k(b: &mut test::Bencher) {
    bench_size(b, 256 * 1024);
}
#[bench]
fn size_19_512k(b: &mut test::Bencher) {
    bench_size(b, 512 * 1024);
}
#[bench]
fn size_20_1m(b: &mut test::Bencher) {
    bench_size(b, 1 * 1024 * 1024);
}
#[bench]
fn size_21_2m(b: &mut test::Bencher) {
    bench_size(b, 2 * 1024 * 1024);
}
#[bench]
fn size_22_4m(b: &mut test::Bencher) {
    bench_size(b, 4 * 1024 * 1024);
}
#[bench]
fn size_23_8m(b: &mut test::Bencher) {
    bench_size(b, 8 * 1024 * 1024);
}

mod receiver_set {
    use ipc_channel::ipc::{self, IpcReceiverSet};
    use test;

    fn gen_select_test(b: &mut test::Bencher, to_send: usize, n: usize) -> () {
        let mut active = Vec::with_capacity(to_send);
        let mut dormant = Vec::with_capacity(n - to_send);
        let mut rx_set = IpcReceiverSet::new().unwrap();
        for _ in 0..to_send {
            let (tx, rx) = ipc::channel().unwrap();
            rx_set.add(rx).unwrap();
            active.push(tx);
        }
        for _ in to_send..n {
            let (tx, rx) = ipc::channel::<()>().unwrap();
            rx_set.add(rx).unwrap();
            dormant.push(tx);
        }
        b.iter(|| {
            for tx in active.iter() {
                tx.send(()).unwrap();
            }
            let mut received = 0;
            while received < to_send {
                for result in rx_set.select().unwrap().into_iter() {
                    let (_, _) = result.unwrap();
                    received += 1;
                }
            }
        });
    }

    fn create_empty_set() -> Result<IpcReceiverSet, ()> {
        Ok(IpcReceiverSet::new().unwrap())
    }

    fn add_n_rxs(rx_set: &mut IpcReceiverSet, n: usize) -> () {
        for _ in 0..n {
            let (_, rx) = ipc::channel::<()>().unwrap();
            rx_set.add(rx).unwrap();
        }
    }

    #[bench]
    fn send_on_1_of_1(b: &mut test::Bencher) -> () {
        gen_select_test(b, 1, 1);
    }

    #[bench]
    fn send_on_1_of_5(b: &mut test::Bencher) -> () {
        gen_select_test(b, 1, 5);
    }

    #[bench]
    fn send_on_2_of_5(b: &mut test::Bencher) -> () {
        gen_select_test(b, 2, 5);
    }

    #[bench]
    fn send_on_5_of_5(b: &mut test::Bencher) -> () {
        gen_select_test(b, 5, 5);
    }

    #[bench]
    fn send_on_1_of_20(b: &mut test::Bencher) -> () {
        gen_select_test(b, 1, 20);
    }

    #[bench]
    fn send_on_5_of_20(b: &mut test::Bencher) -> () {
        gen_select_test(b, 5, 20);
    }

    #[bench]
    fn send_on_20_of_20(b: &mut test::Bencher) -> () {
        gen_select_test(b, 20, 20);
    }

    #[bench]
    fn send_on_1_of_100(b: &mut test::Bencher) -> () {
        gen_select_test(b, 1, 100);
    }

    #[bench]
    fn send_on_5_of_100(b: &mut test::Bencher) -> () {
        gen_select_test(b, 5, 100);
    }
    #[bench]
    fn send_on_20_of_100(b: &mut test::Bencher) -> () {
        gen_select_test(b, 20, 100);
    }

    #[bench]
    fn send_on_100_of_100(b: &mut test::Bencher) -> () {
        gen_select_test(b, 100, 100);
    }

    #[bench]
    fn create_and_destroy_empty_set(b: &mut test::Bencher) -> () {
        b.iter(|| {
            create_empty_set().unwrap();
        });
    }

    #[bench]
    fn create_and_destroy_set_of_10(b: &mut test::Bencher) -> () {
        b.iter(|| {
            let mut rx_set = IpcReceiverSet::new().unwrap();
            add_n_rxs(&mut rx_set, 10);
        });
    }

    #[bench]
    fn create_and_destroy_set_of_5(b: &mut test::Bencher) -> () {
        b.iter(|| {
            let mut rx_set = IpcReceiverSet::new().unwrap();
            add_n_rxs(&mut rx_set, 5);
        });
    }

    #[bench]
    // Benchmark adding and removing closed receivers from the set
    fn add_and_remove_closed_receivers(b: &mut test::Bencher) -> () {
        b.iter(|| {
            let mut rx_set = IpcReceiverSet::new().unwrap();
            {
                {
                    let (_, rx) = ipc::channel::<()>().unwrap();
                    rx_set.add(rx).unwrap();
                }
                // On select Receivers with a "ClosedChannel" event
                // will be closed
                rx_set.select().unwrap();
                let (_, rx) = ipc::channel::<()>().unwrap();
                rx_set.add(rx).unwrap();
            }
        });
    }
}
