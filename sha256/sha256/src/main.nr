// Rotate a u32 to the right by a variable amount.
fn rotateRight32(input : u32, amount : u32) -> u32 {
    (input >> amount) + (input << (32-amount))
}

fn s0(input : u32) -> u32 {
    rotateRight32(input, 7) ^ rotateRight32(input, 18) ^ (input >> 3)
}

fn s1(input : u32) -> u32 {
    rotateRight32(input, 17) ^ rotateRight32(input, 19) ^ (input >> 10)
}

fn S0(input : u32) -> u32 {
    rotateRight32(input, 2) ^ rotateRight32(input, 13) ^ rotateRight32(input, 22)
}

fn S1(input : u32) -> u32 {
    rotateRight32(input, 6) ^ rotateRight32(input, 11) ^ rotateRight32(input, 25)
}

fn ch(e : u32, f : u32, g : u32) -> u32 {
    (e & f) ^ (!e & g)
}

fn maj(a : u32, b : u32, c : u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
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
        let s0val = s0(output[i-15]);
        let s1val = s1(output[i-2]);
        output[i] = s0val + s1val + output[i-16] + output[i-7];
    };
    output
}

fn compress(input : [u32; 64]) -> [u8; 32] {
    let mut output : [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // There are no array globals in noir yet.
    let k_arr : [u32; 64] = [
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

    let mut h0: u32 = 0x6a09e667;
    let mut h1: u32 = 0xbb67ae85;
    let mut h2: u32 = 0x3c6ef372;
    let mut h3: u32 = 0xa54ff53a;
    let mut h4: u32 = 0x510e527f;
    let mut h5: u32 = 0x9b05688c;
    let mut h6: u32 = 0x1f83d9ab;
    let mut h7: u32 = 0x5be0cd19;

    let mut a = h0;
    let mut b = h1;
    let mut c = h2;
    let mut d = h3;
    let mut e = h4;
    let mut f = h5;
    let mut g = h6;
    let mut h = h7;

    for i in 0..63 {
        let S1Val = S1(e);
        let chVal = ch(e, f, g);
        let temp1 = h + S1Val + chVal + k_arr[i] + input[i];

        let S0Val = S0(a);
        let majVal = maj(a, b, c);
        let temp2 = S0Val + majVal;

        h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
    };

    h0 = h0 + a;
    h1 = h1 + b;
    h2 = h2 + c;
    h3 = h3 + d;
    h4 = h4 + e;
    h5 = h5 + f;
    h6 = h6 + g;
    h7 = h7 + h;

    let hs = [h0, h1, h2, h3, h4, h5, h6, h7];
    // Write the 32 bit words to the output array as 4, 8-bit ints.
    for i in 0..8 {
        let mut temp : u32 = hs[i];
        output[4*i] = (temp >> 24) as u8;
        output[4*i+1] = (temp >> 16) as u8;
        output[4*i+2] = (temp >> 8) as u8;
        output[4*i+3] = temp as u8;
    };
    output
}


fn main(input : pub [u8; 64], length : pub u8) {
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

    // Create the message schedule.
    let messageSchedule = createMessageSchedule(preprocessed);

    // Confirm that the message schedule is as expected.
    let expectedSchedule: [u32; 64] = [
        1633837952, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 1633837952, 
        983040, 2108187653, 1610613702, 1050508152, 25426944, 316456923, 
        3806512014, 3357629466, 3073800610, 3854317833, 845560923, 2636160359, 
        3968280267, 1881225380, 3552024379, 2482346367, 996719219, 2952069057, 
        4043988066, 176896406, 1924104970, 2483675966, 610538786, 2672279444, 
        4037431130, 1042573945, 657669027, 206005234, 2215296807, 2049510749, 
        106709978, 4215179723, 3430291419, 3118885940, 2845390439, 2226839261, 
        3256115900, 344409900, 2987358873, 4015503821, 3957764664, 2682456414, 
        2025622859, 2755645205, 1720397816, 4004225740, 313650667,
    ];
    for i in 0..64 {
        constrain messageSchedule[i] == expectedSchedule[i];
    };

    // Compress the message into the output.
    let compressedMessage = compress(messageSchedule);

    // Confirm that the output is as expected.
    // SHA256("abc") = 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let expectedCompressed: [u8; 32] = [
        186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 
        176, 3, 97, 163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173,
    ];
    for i in 0..32 {
        constrain compressedMessage[i] == expectedCompressed[i];
    };
}