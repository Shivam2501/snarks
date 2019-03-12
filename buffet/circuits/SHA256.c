#include <stdint.h>

struct In {uint32_t preimage[16];}; 
struct Out {uint32_t digest[8];};

static const uint32_t K_CONST[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

uint32_t rotateRight(uint32_t in, uint32_t r){
  return (in >> r) | (in << (32 - r));
}

void compute(struct In *input, struct Out *output){
    uint32_t H[8];

    //Initialize H
    H[0] = 0x6a09e667;
    H[1] = 0xbb67ae85;
    H[2] = 0x3c6ef372;
    H[3] = 0xa54ff53a;
    H[4] = 0x510e527f;
    H[5] = 0x9b05688c;
    H[6] = 0x1f83d9ab;
    H[7] = 0x5be0cd19;

    uint32_t words[64];
    uint32_t a,b,c,d,e,f,g,h;
    //hash values
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    int j;
    for(j = 0; j < 16; j++){
        words[j] = input->preimage[j];
    }

    for(j = 16; j < 64; j++){
        uint32_t s0 = rotateRight(words[j - 15], 7) ^ rotateRight(words[j - 15], 18) ^ (words[j - 15] >> 3);
        uint32_t s1 = rotateRight(words[j - 2], 17) ^ rotateRight(words[j - 2], 19) ^ (words[j - 2] >> 10);
        words[j] = words[j - 16] + s0 + words[j - 7] + s1;
    }

    for(j = 0; j < 64; j++){
        uint32_t s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;

        uint32_t s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);

        uint32_t t1 = h + s1 + ch + K_CONST[j] + words[j];
        h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
    }

    H[0] = H[0] + a;
    H[1] = H[1] + b;
    H[2] = H[2] + c;
    H[3] = H[3] + d;
    H[4] = H[4] + e;
    H[5] = H[5] + f;
    H[6] = H[6] + g;
    H[7] = H[7] + h;

    for(j = 0; j < 8; j++){
        output->digest[j] = H[j];
    }
}
