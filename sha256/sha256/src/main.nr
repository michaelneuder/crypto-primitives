global h0: comptime u32 = 0x6a09e667;
global h1: comptime u32 = 0xbb67ae85;
global h2: comptime u32 = 0x3c6ef372;
global h3: comptime u32 = 0xa54ff53a;
global h4: comptime u32 = 0x510e527f;
global h5: comptime u32 = 0x9b05688c;
global h6: comptime u32 = 0x1f83d9ab;
global h7: comptime u32 = 0x5be0cd19;

// Rotate a u32 to the right by a variable amount.
fn rotateRight32(input : u32, amount : u32) -> u32 {
    let res = (input >> amount) + (input << (32-amount));
    res
}

fn s0(input : u32) -> u32 {
    let res = rotateRight32(input, 7) ^ rotateRight32(input, 18) ^ (input >> 3);
    res
}

// Add padding to the input message.
fn preprocess(input : [u8; 64], length : u8) -> [u8; 64] {
    let mut output = input;
    let numZeros : u8 = 64 - (length + 1 + 8);
    for i in 0..63 {
        let intI = i as u8;
        if intI < length {
            output[i] = input[i];
        }
        if intI == length {
            output[i] = 128;
        }
        if intI > length & intI < length + numZeros {
            output[i] = 0;
        }
    };
    output[63] = length * 8;
    output 
}

fn createMessageSchedule(preprocessed : [u8; 64]) -> [u32; 64] {
    let mut output : [u32; 64] = [
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // Copy in original message.
    for i in 0..16 {
        // Shift and LAND bits of the u32 message chunk.
        let mut temp : u32 = preprocessed[4*i] as u32;
        let mut out = (temp << 24);
        temp = preprocessed[4*i+1] as u32;
        out = out + (temp << 16);
        temp = preprocessed[4*i+2] as u32;
        out = out + (temp << 8);
        temp = preprocessed[4*i+3] as u32;
        out = out + temp;
        output[i] = out;
    };

    // Do the rotations.
    for i in 16..64 {
        let inp = output[i-15] as u32;
        let s0val = s0(inp);
        output[i] = s0val;
        if i == 30 {
            constrain inp == 24;
            let s0val2 = s0(24);
            constrain s0val2 == 805699587;
        }
    };
    output
}

fn main(input : pub [u8; 64], length : pub u8) {
    // There are no array globals in noir yet.
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

    // Run preprocess padding.
    let preprocessed = preprocess(input, length);

    // Confirm that the preprocessed message is as expected.
    let expectedPreprocessed: [u8; 64] = [
        97, 98, 99, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24,
    ];
    for i in 0..64 {
        constrain preprocessed[i] == expectedPreprocessed[i];
    };

    let messageSchedule = createMessageSchedule(preprocessed);

    // Confirm that the message schedule is as expected.
    let expectedSchedule: [u32; 64] = [
        1633837952, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    for i in 0..64 {
        constrain messageSchedule[i] == expectedSchedule[i];
    };
}