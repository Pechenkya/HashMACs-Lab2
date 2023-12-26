#![allow(dead_code, non_snake_case)]
use std::{time::SystemTime, collections::HashMap};

use sha1::{Sha1, Digest};
use rand_core::RngCore;
use rand::thread_rng;
use rayon::prelude::*;
use hex;

static TWO: usize = 2;
// static N: usize = 16;
static N: usize = 32;
static N_BYTES: usize = N / 8;
static SUFFIX: usize = 20 - N_BYTES;
static PAD_W: usize = 128 - N;
static PAD_W_BYTES: usize = PAD_W / 8;
static T : usize = 10000;

fn print_bytes(bytes: &[u8]) {
    print!("Array: [");
    for i in 0..bytes.len() {
        print!("{}", bytes[i]);
        if i < bytes.len() - 1 {
            print!(", ");
        }
    }
    println!("]")
}

fn generate(bytes: usize) -> Vec<u8> {
    let mut value = vec![0u8; bytes];
    thread_rng().fill_bytes(&mut value);

    value
}

fn h_n_bytes(byts: &[u8]) -> Vec<u8> {
    let h_val : [u8; 20] = Sha1::new_with_prefix(byts).finalize().into();
    let res: &[u8] = &h_val[SUFFIX..];

    res.to_owned()
}

fn print_data(data: &Vec<u8>) {
    println!("{}", String::from_utf8_lossy(&data));
}

fn print_hex_formatted(hash: &Vec<u8>) {
    println!("{:}\t{:}", hex::encode(hash[..20-N_BYTES].to_vec()), hex::encode(&hash[20-N_BYTES..].to_vec()))
}

// ================== Атака пошуку прообразу ==================

fn find_preimage(L: usize, p_table: &HashMap<Vec<u8>, Vec<u8>>, r: &[u8], h_val: &[u8]) -> Option<Vec<u8>>{
    let mut y = [r, &h_val].concat();
    let mut j_found = L;
    for j in 0..L {
        if p_table.contains_key(&y[PAD_W_BYTES..]) {
            j_found = j;
            break;
        }

        let h = h_n_bytes(&y);
        y[PAD_W_BYTES..].clone_from_slice(&h);
    }

    if j_found != L {
        let mut x = [r, p_table.get(&y[PAD_W_BYTES..]).unwrap()].concat();
        for _ in 0..L - j_found - 1 {  
            let h = h_n_bytes(&x);
            x[PAD_W_BYTES..].clone_from_slice(&h);
        }
        return Some(x);
    }

    None
}

fn check_preimage(preimage: &Vec<u8>, h_val: &Vec<u8>) -> bool{
    h_n_bytes(&preimage) == *h_val
}

// ============================================================

// ================== Атака 1 (одна таблиця) ==================

// ------------- Parallel generation of the table -------------


fn append_value(L: usize, r: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // let R = |x : &[u8]| [r, x].concat();

    let x0 = generate(N_BYTES);
    
    let mut padded_value = [r, &x0.clone()].concat();
    for _ in 0..L {
        let h = h_n_bytes(&padded_value);
        padded_value[PAD_W_BYTES..].clone_from_slice(&h);
    }

    (padded_value[PAD_W_BYTES..].to_vec(), x0.clone()) 
}

fn generate_pre_table_parallel(K: usize, L: usize) -> (HashMap<Vec<u8>, Vec<u8>>, Vec<u8>){
    let r = generate(PAD_W_BYTES);

    let table: HashMap<_, _> = (0..K).into_par_iter().map(|_| append_value(L, &r)).collect();

    // println!("Parallel execution complete, table size: {}", table.len());

    (table, r)
}

// ------------------------------------------------------------

fn launch_attack_1() -> Vec<(usize, usize, usize)> {
    let K_arr_1 = [TWO.pow(20), TWO.pow(22), TWO.pow(24)];
    let L_arr_1 = [TWO.pow(10), TWO.pow(11), TWO.pow(12)];

    
    // let K_arr_1 = [TWO.pow(10), TWO.pow(12), TWO.pow(14)];
    // let L_arr_1 = [TWO.pow(5), TWO.pow(6), TWO.pow(7)];
    
    let mut atk1_results = Vec::new();
    
    for K in K_arr_1 {
        for L in L_arr_1 {
            let timer = SystemTime::now();

            let mut run_res = (0, 0, 0);
            let (table, r) = generate_pre_table_parallel(K, L);

            for _ in 0..T {
                let value = generate(32);
                let h_val = h_n_bytes(&value);

                match find_preimage(L, &table, &r, &h_val) {
                    Some(preimage) => {
                        if check_preimage(&preimage, &h_val) {
                            run_res.2 = run_res.2 + 1;
                        }
                        else { 
                            run_res.1 = run_res.1 + 1;
                        }
                    }
                    None => run_res.0 = run_res.0 + 1
                }
            }

            atk1_results.push(run_res);
            println!("{}, {}, {}", run_res.0, run_res.1, run_res.2);
            println!("K = {}, L = {}: Elapsed time: {}", K, L, timer.elapsed().unwrap().as_secs());
        }
    }

    return atk1_results;
}

fn atk1_one_succ_instance() {
    let K = TWO.pow(20);
    let L = TWO.pow(10);

    
    println!("Starting Attack 1 with K = {}, L = {}", K, L);
    // let timer = SystemTime::now();

    let (table, r) = generate_pre_table_parallel(K, L);

    // let value = generate(32);
    // println!("Initial value: ");
    // print_bytes(&value);
    // let h_val = h_n_bytes(&value);
    // print!("Hash: ");
    // print_hex_formatted(&Sha1::new_with_prefix(value).finalize().as_slice().to_owned());

    loop {
        let value = generate(32);
        let h_val = h_n_bytes(&value);

        match find_preimage(L, &table, &r, &h_val) {
            Some(preimage) => {
                if check_preimage(&preimage, &h_val) {
                    println!("Initial value: ");
                    print_bytes(&value);
                    print!("Hash: ");
                    print_hex_formatted(&Sha1::new_with_prefix(value).finalize().as_slice().to_owned());

                    println!("Preimage found :D");
                    println!("Preimage: ");
                    print_bytes(&preimage);
                    print!("Hash: ");
                    print_hex_formatted(&Sha1::new_with_prefix(preimage).finalize().as_slice().to_owned());
                    break;
                }
                // else { 
                //     println!("Found fake preimage :(");
                //     println!("Fake Preimage: ");
                //     print_bytes(&preimage);
                //     print!("Hash: ");
                //     print_hex_formatted(&Sha1::new_with_prefix(preimage).finalize().as_slice().to_owned());
                // }
            }
            None => () // println!("Preimage wasn't found :("),
        }
    }
    

    // println!("Elapsed time: {}", timer.elapsed().unwrap().as_secs());
}

// ============================================================

// ================== Атака 2 (K таблиць) =====================

// ------------- Parallel generation of K tables --------------

fn generate_K_tables_parallel(K: usize, L: usize) -> (Vec<HashMap<Vec<u8>, Vec<u8>>>, Vec<Vec<u8>>){
    let mut Tables = Vec::new();
    let mut r_s = Vec::new();

    (0..K).into_par_iter().map(|_| generate_pre_table_parallel(K, L))
                          .unzip_into_vecs(&mut Tables, &mut r_s);

    (Tables, r_s)
}

// ------------------------------------------------------------

fn launch_attack_2() -> Vec<(usize, usize)> {
    let K_arr_2 = [TWO.pow(10), TWO.pow(11), TWO.pow(12)];
    let L_arr_2 = [TWO.pow(10), TWO.pow(11), TWO.pow(12)];

    
    // let K_arr_2 = [TWO.pow(5), TWO.pow(6), TWO.pow(7)];
    // let L_arr_2 = [TWO.pow(5), TWO.pow(6), TWO.pow(7)];
    
    let mut atk2_results = Vec::new();
    
    for K in K_arr_2 {
        for L in L_arr_2 {
            println!("K = {}, L = {}: Multitables started", K, L);
            let timer = SystemTime::now();
            // (<fail>, <succ>)
            let mut run_res = (0, 0);
            let (Tables, r_s) = generate_K_tables_parallel(K, L);
            println!("K = {}, L = {}: Tables ready", K, L);

            for _ in 0..T {
                let value = generate(32);
                let h_val = h_n_bytes(&value);

                if (0..K).into_par_iter().any(|i| {
                    match find_preimage(L, &Tables[i], &r_s[i], &h_val) {
                        Some(pi) => check_preimage(&pi, &h_val),
                        None => false
                    }
                }) {
                    run_res.1 = run_res.1 + 1;
                }
                else {
                    run_res.0 = run_res.0 + 1;
                }
            }

            atk2_results.push(run_res);
            println!("{}, {}", run_res.0, run_res.1);
            println!("K = {}, L = {}: Elapsed time: {}", K, L, timer.elapsed().unwrap().as_secs());
        }
    }

    return atk2_results;
}

fn atk2_one_succ_instance() {
    let K = TWO.pow(10);
    let L = TWO.pow(10);

    
    println!("Starting Attack 2 with K = {}, L = {}", K, L);
    // let timer = SystemTime::now();

    let (Tables, r_s) = generate_K_tables_parallel(K, L);

    loop {
        let value = generate(32);
        let h_val = h_n_bytes(&value);


        let preimage_idx = (0..K).into_par_iter().find_any(|i| {
            match find_preimage(L, &Tables[*i], &r_s[*i], &h_val) {
                Some(pi) => check_preimage(&pi, &h_val),
                None => false
            }
        });

        match preimage_idx {
            Some(idx) => {
                let preimage = find_preimage(L, &Tables[idx], &r_s[idx], &h_val).unwrap();

                println!("Initial value: ");
                print_bytes(&value);
                print!("Hash: ");
                print_hex_formatted(&Sha1::new_with_prefix(value).finalize().as_slice().to_owned());

                println!("Preimage found :D");
                println!("Preimage: ");
                print_bytes(&preimage);
                print!("Hash: ");
                print_hex_formatted(&Sha1::new_with_prefix(preimage).finalize().as_slice().to_owned());
                break;
            }
            None => ()
        }

    }
    

    // println!("Elapsed time: {}", timer.elapsed().unwrap().as_secs());
}

// ============================================================

fn main() {
    let now = SystemTime::now();

    // atk1_one_succ_instance();

    // atk2_one_succ_instance();

    // let results1 = launch_attack_1();
    // println!("Attack 1 results: ");
    // println!("Not found, Fake, Real");
    // for (a, b, c) in results1 {
    //     println!("{}, {}, {}", a, b, c);
    // }

    // let results2 = launch_attack_2();
    // println!("Attack 2 results: ");
    // println!("Not found, Found");
    // for (a, b) in results2 {
    //     println!("{}, {}", a, b);
    // }

    println!("Elapsed time: {}", now.elapsed().unwrap().as_secs());
}
