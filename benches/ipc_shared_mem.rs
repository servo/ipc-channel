use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};
use ipc_channel::ipc::{self, IpcSharedMemory};

#[inline]
fn on_recv<const MUT: bool>(mut ism: IpcSharedMemory) -> IpcSharedMemory {
    if MUT {
        let data = unsafe { ism.deref_mut() };
        for d in data {
            *d += 1;
        }
        ism
    } else {
        let mut data = ism.to_vec();
        for d in &mut data {
            *d += 1;
        }
        IpcSharedMemory::from_bytes(&data)
    }
}

fn ping_pong_mut_shared_mem<const MUT: bool, const SIZE: usize, const COUNT: u8>(
    criterion: &mut Criterion,
) {
    criterion.bench_function(
        &format!(
            "ping_pong_shared_mem{}_{SIZE}_{COUNT}",
            if MUT { "_mut" } else { "" }
        ),
        |bencher| {
            bencher.iter_custom(|_| {
                let (tx1, rx1) = ipc::channel().unwrap();
                let (tx2, rx2) = ipc::channel().unwrap();
                let tx = tx1.clone();
                let _t1 = std::thread::spawn(move || {
                    for _i in 0..=COUNT / 2 {
                        tx2.send(on_recv::<MUT>(rx1.recv().unwrap())).unwrap();
                    }
                });
                let t2 = std::thread::spawn(move || {
                    for _i in 0..COUNT / 2 {
                        tx1.send(on_recv::<MUT>(rx2.recv().unwrap())).unwrap();
                    }
                    rx2.recv().unwrap().to_vec()
                });
                let start = Instant::now();
                tx.send(IpcSharedMemory::from_byte(0, SIZE)).unwrap();
                let data = t2.join().unwrap();
                let duration = start.elapsed();
                assert!(data.iter().all(|d| *d == (COUNT / 2) * 2 + 1));
                duration
            });
        },
    );
}

criterion_group!(
    benches,
    ping_pong_mut_shared_mem<true, {4*1024*1024}, 100>,
    ping_pong_mut_shared_mem<false, {4*1024*1024}, 100>,
    ping_pong_mut_shared_mem<true, {4*1024*1024}, 125>,
    ping_pong_mut_shared_mem<false, {4*1024*1024}, 125>,
);
criterion_main!(benches);
