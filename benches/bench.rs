#![feature(test)]

extern crate ipc_channel;
extern crate test;

/// Allows doing multiple inner iterations per bench.iter() run.
///
/// This is mostly to amortise the overhead of spawning a thread in the benchmark
/// when sending larger messages (that might be fragmented).
///
/// Note that you need to compensate the displayed results
/// for the proportionally longer runs yourself,
/// as the benchmark framework doesn't know about the inner iterations...
const ITERATIONS: usize = 1;

mod platform {
    extern crate crossbeam_utils;

    use crate::ITERATIONS;
    use ipc_channel::platform;

    use crate::test;
    use std::sync::{mpsc, Mutex};

    #[bench]
    fn create_channel(b: &mut test::Bencher) {
        b.iter(|| {
            for _ in 0..ITERATIONS {
                platform::channel().unwrap();
            }
        });
    }

    fn bench_transfer_data(b: &mut test::Bencher, size: usize) {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let (tx, rx) = platform::channel().unwrap();

        let (wait_tx, wait_rx) = mpsc::channel();
        let wait_rx = Mutex::new(wait_rx);

        if size > platform::OsIpcSender::get_max_fragment_size() {
            b.iter(|| {
                crossbeam_utils::thread::scope(|scope| {
                    let tx = tx.clone();
                    scope.spawn(|_| {
                        let wait_rx = wait_rx.lock().unwrap();
                        let tx = tx;
                        for _ in 0..ITERATIONS {
                            tx.send(&data, vec![], vec![], vec![]).unwrap();
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
                    tx.send(&data, vec![], vec![], vec![]).unwrap();
                    rx.recv().unwrap();
                }
                0
            });
        }
    }

    #[bench]
    fn transfer_data_00_1(b: &mut test::Bencher) {
        bench_transfer_data(b, 1);
    }
    #[bench]
    fn transfer_data_01_2(b: &mut test::Bencher) {
        bench_transfer_data(b, 2);
    }
    #[bench]
    fn transfer_data_02_4(b: &mut test::Bencher) {
        bench_transfer_data(b, 4);
    }
    #[bench]
    fn transfer_data_03_8(b: &mut test::Bencher) {
        bench_transfer_data(b, 8);
    }
    #[bench]
    fn transfer_data_04_16(b: &mut test::Bencher) {
        bench_transfer_data(b, 16);
    }
    #[bench]
    fn transfer_data_05_32(b: &mut test::Bencher) {
        bench_transfer_data(b, 32);
    }
    #[bench]
    fn transfer_data_06_64(b: &mut test::Bencher) {
        bench_transfer_data(b, 64);
    }
    #[bench]
    fn transfer_data_07_128(b: &mut test::Bencher) {
        bench_transfer_data(b, 128);
    }
    #[bench]
    fn transfer_data_08_256(b: &mut test::Bencher) {
        bench_transfer_data(b, 256);
    }
    #[bench]
    fn transfer_data_09_512(b: &mut test::Bencher) {
        bench_transfer_data(b, 512);
    }
    #[bench]
    fn transfer_data_10_1k(b: &mut test::Bencher) {
        bench_transfer_data(b, 1 * 1024);
    }
    #[bench]
    fn transfer_data_11_2k(b: &mut test::Bencher) {
        bench_transfer_data(b, 2 * 1024);
    }
    #[bench]
    fn transfer_data_12_4k(b: &mut test::Bencher) {
        bench_transfer_data(b, 4 * 1024);
    }
    #[bench]
    fn transfer_data_13_8k(b: &mut test::Bencher) {
        bench_transfer_data(b, 8 * 1024);
    }
    #[bench]
    fn transfer_data_14_16k(b: &mut test::Bencher) {
        bench_transfer_data(b, 16 * 1024);
    }
    #[bench]
    fn transfer_data_15_32k(b: &mut test::Bencher) {
        bench_transfer_data(b, 32 * 1024);
    }
    #[bench]
    fn transfer_data_16_64k(b: &mut test::Bencher) {
        bench_transfer_data(b, 64 * 1024);
    }
    #[bench]
    fn transfer_data_17_128k(b: &mut test::Bencher) {
        bench_transfer_data(b, 128 * 1024);
    }
    #[bench]
    fn transfer_data_18_256k(b: &mut test::Bencher) {
        bench_transfer_data(b, 256 * 1024);
    }
    #[bench]
    fn transfer_data_19_512k(b: &mut test::Bencher) {
        bench_transfer_data(b, 512 * 1024);
    }
    #[bench]
    fn transfer_data_20_1m(b: &mut test::Bencher) {
        bench_transfer_data(b, 1 * 1024 * 1024);
    }
    #[bench]
    fn transfer_data_21_2m(b: &mut test::Bencher) {
        bench_transfer_data(b, 2 * 1024 * 1024);
    }
    #[bench]
    fn transfer_data_22_4m(b: &mut test::Bencher) {
        bench_transfer_data(b, 4 * 1024 * 1024);
    }
    #[bench]
    fn transfer_data_23_8m(b: &mut test::Bencher) {
        bench_transfer_data(b, 8 * 1024 * 1024);
    }
}

mod ipc {
    use crate::ITERATIONS;
    use ipc_channel::ipc;

    use crate::test;

    #[bench]
    fn transfer_empty(b: &mut test::Bencher) {
        let (tx, rx) = ipc::channel().unwrap();
        b.iter(|| {
            for _ in 0..ITERATIONS {
                tx.send(()).unwrap();
                rx.recv().unwrap()
            }
        });
    }

    fn bench_transfer_senders(b: &mut test::Bencher, count: usize) {
        let (main_tx, main_rx) = ipc::channel().unwrap();
        let transfer_txs: Vec<_> = (0..count)
            .map(|_| ipc::channel::<()>().unwrap())
            .map(|(tx, _)| tx)
            .collect();
        let mut transfer_txs = Some(transfer_txs);
        b.iter(|| {
            for _ in 0..ITERATIONS {
                main_tx.send(transfer_txs.take().unwrap()).unwrap();
                transfer_txs = Some(main_rx.recv().unwrap());
            }
        });
    }

    #[bench]
    fn transfer_senders_00(b: &mut test::Bencher) {
        bench_transfer_senders(b, 0);
    }

    #[bench]
    fn transfer_senders_01(b: &mut test::Bencher) {
        bench_transfer_senders(b, 1);
    }

    #[bench]
    fn transfer_senders_08(b: &mut test::Bencher) {
        bench_transfer_senders(b, 8);
    }

    #[bench]
    fn transfer_senders_64(b: &mut test::Bencher) {
        bench_transfer_senders(b, 64);
    }

    fn bench_transfer_receivers(b: &mut test::Bencher, count: usize) {
        let (main_tx, main_rx) = ipc::channel().unwrap();
        let transfer_rxs: Vec<_> = (0..count)
            .map(|_| ipc::channel::<()>().unwrap())
            .map(|(_, rx)| rx)
            .collect();
        let mut transfer_rxs = Some(transfer_rxs);
        b.iter(|| {
            for _ in 0..ITERATIONS {
                main_tx.send(transfer_rxs.take().unwrap()).unwrap();
                transfer_rxs = Some(main_rx.recv().unwrap());
            }
        });
    }

    #[bench]
    fn transfer_receivers_00(b: &mut test::Bencher) {
        bench_transfer_receivers(b, 0);
    }

    #[bench]
    fn transfer_receivers_01(b: &mut test::Bencher) {
        bench_transfer_receivers(b, 1);
    }

    #[bench]
    fn transfer_receivers_08(b: &mut test::Bencher) {
        bench_transfer_receivers(b, 8);
    }

    #[bench]
    fn transfer_receivers_64(b: &mut test::Bencher) {
        bench_transfer_receivers(b, 64);
    }

    mod receiver_set {
        use crate::ITERATIONS;
        use ipc_channel::ipc::{self, IpcReceiverSet};

        use crate::test;

        // Benchmark selecting over a set of `n` receivers,
        // with `to_send` of them actually having pending data.
        fn bench_send_on_m_of_n(b: &mut test::Bencher, to_send: usize, n: usize) {
            let mut senders = Vec::with_capacity(n);
            let mut rx_set = IpcReceiverSet::new().unwrap();
            for _ in 0..n {
                let (tx, rx) = ipc::channel().unwrap();
                rx_set.add(rx).unwrap();
                senders.push(tx);
            }
            b.iter(|| {
                for _ in 0..ITERATIONS {
                    for tx in senders.iter().take(to_send) {
                        tx.send(()).unwrap();
                    }
                    let mut received = 0;
                    while received < to_send {
                        received += rx_set.select().unwrap().len();
                    }
                }
            });
        }

        #[bench]
        fn send_on_1_of_1(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 1, 1);
        }

        #[bench]
        fn send_on_1_of_5(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 1, 5);
        }

        #[bench]
        fn send_on_2_of_5(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 2, 5);
        }

        #[bench]
        fn send_on_5_of_5(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 5, 5);
        }

        #[bench]
        fn send_on_1_of_20(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 1, 20);
        }

        #[bench]
        fn send_on_5_of_20(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 5, 20);
        }

        #[bench]
        fn send_on_20_of_20(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 20, 20);
        }

        #[bench]
        fn send_on_1_of_100(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 1, 100);
        }

        #[bench]
        fn send_on_5_of_100(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 5, 100);
        }
        #[bench]
        fn send_on_20_of_100(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 20, 100);
        }

        #[bench]
        fn send_on_100_of_100(b: &mut test::Bencher) {
            bench_send_on_m_of_n(b, 100, 100);
        }

        fn create_set_of_n(n: usize) -> IpcReceiverSet {
            let mut rx_set = IpcReceiverSet::new().unwrap();
            for _ in 0..n {
                let (_, rx) = ipc::channel::<()>().unwrap();
                rx_set.add(rx).unwrap();
            }
            rx_set
        }

        #[bench]
        fn create_and_destroy_empty_set(b: &mut test::Bencher) {
            b.iter(|| {
                for _ in 0..ITERATIONS {
                    create_set_of_n(0);
                }
            });
        }

        #[bench]
        fn create_and_destroy_set_of_1(b: &mut test::Bencher) {
            b.iter(|| {
                for _ in 0..ITERATIONS {
                    create_set_of_n(1);
                }
            });
        }

        #[bench]
        fn create_and_destroy_set_of_10(b: &mut test::Bencher) {
            b.iter(|| {
                for _ in 0..ITERATIONS {
                    create_set_of_n(10);
                }
            });
        }

        #[bench]
        fn create_and_destroy_set_of_100(b: &mut test::Bencher) {
            b.iter(|| {
                for _ in 0..ITERATIONS {
                    create_set_of_n(100);
                }
            });
        }

        // Benchmark performance of removing closed receivers from set.
        // This also includes the time for adding receivers,
        // as there is no way to measure the removing in isolation.
        fn bench_remove_closed(b: &mut test::Bencher, n: usize) {
            b.iter(|| {
                for _ in 0..ITERATIONS {
                    // We could keep adding/removing senders to the same set,
                    // instead of creating a new one in each iteration.
                    // However, this would actually make the results harder to compare...
                    let mut rx_set = create_set_of_n(n);

                    let mut dropped_count = 0;
                    while dropped_count < n {
                        // On `select()`, receivers with a "ClosedChannel" event will be closed,
                        // and automatically dropped from the set.
                        dropped_count += rx_set.select().unwrap().len();
                    }
                }
            });
        }

        #[bench]
        fn add_and_remove_1_closed_receivers(b: &mut test::Bencher) {
            bench_remove_closed(b, 1);
        }

        #[bench]
        fn add_and_remove_10_closed_receivers(b: &mut test::Bencher) {
            bench_remove_closed(b, 10);
        }

        #[bench]
        fn add_and_remove_100_closed_receivers(b: &mut test::Bencher) {
            bench_remove_closed(b, 100);
        }
    }
}
