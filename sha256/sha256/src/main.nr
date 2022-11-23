global h0: comptime u32 = 0x6a09e667;
global h1: comptime u32 = 0xbb67ae85;
global h2: comptime u32 = 0x3c6ef372;
global h3: comptime u32 = 0xa54ff53a;
global h4: comptime u32 = 0x510e527f;
global h5: comptime u32 = 0x9b05688c;
global h6: comptime u32 = 0x1f83d9ab;
global h7: comptime u32 = 0x5be0cd19;

fn preprocess(input : u24) -> u512 {
    let mut res : u512 = 0;
    for _unused in 0..1 {
        res = res * 2;
    }
    res
}

// fn leftShift(input : u64, amount : u4) -> u64 {
//     let mut res : u64 = input;
//     for _i in 0..amount {
//         res = res * 2;
//     };
//     res
// }

fn main(input : pub u24) {
    let k_arr = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    
    constrain k_arr[0] != k_arr[1];
 
    let inpIn32 = input as u32;
    constrain inpIn32 == 6382179;

    let preprocessed = preprocess(input);
    constrain inpIn32 == 12764358;
}