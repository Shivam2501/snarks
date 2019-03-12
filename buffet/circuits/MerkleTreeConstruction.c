#include <stdint.h>

#define NUM_LEAF 8

struct Leaf {
    uint32_t node[16];
};

struct hash {
    uint32_t array[8];
};

struct In {
    struct Leaf nodes[NUM_LEAF];
};

struct Out {
    uint32_t root[8];
};

struct Leaf concat(uint32_t* a1, uint32_t* a2) {
    struct Leaf res;
    int i;
    for (i = 0; i < 8; i++) {
        res.node[i] = a1[i];
        res.node[i + 8] = a2[i];
    }
    return res;
}

const uint32_t K_CONST[64] = {
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

struct hash sha2(struct Leaf* preimage){
    struct hash H;

    //Initialize H
    H.array[0] = 0x6a09e667;
    H.array[1] = 0xbb67ae85;
    H.array[2] = 0x3c6ef372;
    H.array[3] = 0xa54ff53a;
    H.array[4] = 0x510e527f;
    H.array[5] = 0x9b05688c;
    H.array[6] = 0x1f83d9ab;
    H.array[7] = 0x5be0cd19;

    uint32_t words[64];
    uint32_t a,b,c,d,e,f,g,h;
    //hash values
    a = H.array[0];
    b = H.array[1];
    c = H.array[2];
    d = H.array[3];
    e = H.array[4];
    f = H.array[5];
    g = H.array[6];
    h = H.array[7];

    int j;
    for(j = 0; j < 16; j++){
        words[j] = preimage->node[j];
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

    H.array[0] = H.array[0] + a;
    H.array[1] = H.array[1] + b;
    H.array[2] = H.array[2] + c;
    H.array[3] = H.array[3] + d;
    H.array[4] = H.array[4] + e;
    H.array[5] = H.array[5] + f;
    H.array[6] = H.array[6] + g;
    H.array[7] = H.array[7] + h;

    return H;
}

void compute(struct In *input, struct Out *output) {
    uint32_t hashTree[NUM_LEAF * 2 - 1][8];

    int i, j;
    for (i = 0; i < NUM_LEAF; i++) {
        struct hash digest = sha2(&(input->nodes[i]));
        for (j = 0; j < 8; j++) {
            hashTree[i + NUM_LEAF - 1][j] = digest.array[j];
        }
    }

    for (i = NUM_LEAF - 2; i >= 0; i--) {
        struct Leaf res = concat(hashTree[i * 2 + 1], hashTree[i * 2 + 2]);
        struct hash digest = sha2(&res);
        for (j = 0; j < 8; j++) {
            hashTree[i][j] = digest.array[j];
        }
    }

    for (j = 0; j < 8; j++) {
        output->root[j] = hashTree[0][j];
    }
}
