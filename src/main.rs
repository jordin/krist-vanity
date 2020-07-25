#[macro_use]
extern crate clap;

use std::time::*;

use clap::App;
use colored::*;
use ocl::*;
use ocl::builders::DeviceSpecifier;

fn find_address(address: &str, work_size: u64, iterations: u64, mut base: u64, device_spec: DeviceSpecifier) -> ocl::Result<u64> {
    let src = format!(
        "#define DESIRED_LENGTH {}\n#define DESIRED_ADDRESS {}\n#define ITERATIONS {}\n{}\n{}",
        address.len(),
        address
            .chars()
            .map(|c| format!("'{}'", c))
            .collect::<Vec<_>>()
            .join(","),
        iterations,
        include_str!("./tables.cl"),
        include_str!("./vanity_gen.cl")
    );

    let pro_que = ProQue::builder().src(src).dims(1usize).device(device_spec).build()?;
    let solution_buffer = pro_que.create_buffer::<u64>()?;

    let kernel = pro_que
        .kernel_builder("check")
        .global_work_size(work_size as usize)
        .arg(&solution_buffer)
        .arg(base)
        .build()?;

    let mut solution_vec = vec![0u64; solution_buffer.len()];

    let attempts_per_iteration = work_size * iterations;
    let start = Instant::now();

    loop {
        kernel.set_arg(1, base)?;

        unsafe {
            kernel.enq()?;
        };

        solution_buffer.read(&mut solution_vec).enq()?;

        if solution_vec[0] != 0 {
            return Ok(solution_vec[0]);
        }

        base += attempts_per_iteration;

        println!(
            "Processing {} addresses per second",
            format!("{:.2}", base as f64 / start.elapsed().as_secs_f64()).green()
        );
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let work_size = matches
        .value_of("WORK_SIZE")
        .and_then(|str_work_size| str_work_size.parse::<u64>().ok())
        .unwrap_or(262144);
    let device_id = matches
        .value_of("GPU")
        .and_then(|str_gpu| str_gpu.parse::<isize>().ok())
        .unwrap_or(0);
    let iterations = matches
        .value_of("ITERATIONS")
        .and_then(|str_iterations| str_iterations.parse::<u64>().ok())
        .unwrap_or(64);
    let base_address = matches
        .value_of("BASE")
        .and_then(|str_base| str_base.parse::<u64>().ok())
        .unwrap_or(0);
    let target_address = matches
        .value_of("ADDRESS")
        .expect("Please provide an address");

    let device_spec = if device_id < 0 {
        DeviceSpecifier::All
    } else {
        let devices: Vec<Device> = Platform::list()
            .iter()
            .flat_map(|platform| Device::list_all(platform).unwrap_or(vec![]))
            .collect();

        DeviceSpecifier::Single(devices[device_id as usize])
    };

    let found_password = find_address(target_address, work_size, iterations, base_address, device_spec)
        .expect("Error occured when computing with OpenCL");

    println!(
        "Found password for {}: {}",
        target_address.blue(),
        found_password.to_string().green()
    );
}
