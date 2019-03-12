#include <stdint.h>

#define HEIGHT 8

struct Digest {
    uint32_t array[8];
};

struct MerkleAuthPath {
    uint64_t directionSelector;
    struct Digest digests[HEIGHT];
};

struct Coin {
    uint64_t value;
    uint32_t rho[8];
    uint32_t rand[12];
    struct Digest pubKey;
};

struct In {
    struct Digest root;
    uint64_t pubVal;
    struct Digest h_sig;
    struct MerkleAuthPath authPath1;
    struct MerkleAuthPath authPath2;
    struct Coin c1_old;
    struct Coin c2_old;
    struct Coin c1_new;
    struct Coin c2_new;
    struct Digest c1_old_comm;
    struct Digest c2_old_comm;
    struct Digest sk1_old;
    struct Digest sk2_old;
};

struct Out {
    struct Digest sn1_old;
    struct Digest sn2_old;
    struct Digest c1_new_comm;
    struct Digest c2_new_comm;
    struct Digest h1;
    struct Digest h2;
};

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

struct Digest sha2(uint32_t* preimage){
    struct Digest H;

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
        words[j] = preimage[j];
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

struct Digest computeMerkleRoot(struct MerkleAuthPath* authPath, struct Digest* leaf) {
    uint32_t inputToNextHash[16];

    int i, j;
    struct Digest currentDigest;
    for (j = 0; j < 8; j++) {
        currentDigest.array[j] = leaf->array[j];
    }

    for (i = 0; i < HEIGHT; i++) {
        for (j = 0; j < 16; j++) {
            if ((authPath->directionSelector >> i) & 1)
                inputToNextHash[j] = j >= 8 ? currentDigest.array[j - 8] : authPath->digests[i].array[j];
            else
                inputToNextHash[j] = j < 8 ? currentDigest.array[j] : authPath->digests[i].array[j - 8];
        }
        currentDigest = sha2(inputToNextHash);
    }

    return currentDigest;
}

uint32_t* truncate(uint32_t* words, int n) {
    words[7] = words[7] >> n;
    int i;
    for (i = 6; i >= 0; i--) {
        words[i + 1] = words[i + 1] | (words[i] << (32 - n));
        words[i] = words[i] >> n;
    }
    return words;
}

struct Digest prfAddr(uint32_t* x) {
    uint32_t z[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t input[16];
    int i;
    for (i = 0; i < 16; i++) {
        if (i < 8) {
            input[i] = x[i];
        } else if (i == 8) {
            input[i] = z[i - 8] | 0u;
        } else {
            input[i] = z[i - 8];
        }
    }
    return sha2(input);
}

struct Digest prfSn(uint32_t* x, uint32_t* z) {
    uint32_t input[16];
    int i;

    z = truncate(z, 2);
    for (i = 0; i < 16; i++) {
        if (i < 8) {
            input[i] = x[i];
        } else if (i == 8) {
            input[i] = z[i - 8] | 0x40000000u;
        } else {
            input[i] = z[i - 8];
        }
    }
    return sha2(input);
}

struct Digest prfPk(uint32_t* x, uint32_t* z) {
    uint32_t input[16];
    int i;

    z = truncate(z, 3);
    for (i = 0; i < 16; i++) {
        if (i < 8) {
            input[i] = x[i];
        } else if (i == 8) {
            input[i] = z[i - 8] | 0x80000000u;
        } else {
            input[i] = z[i - 8];
        }
    }
    return sha2(input);
}

struct Digest comm_r(uint32_t* r, uint32_t* a_pk, uint32_t* rho) {
    uint32_t input[16];
    struct Digest temp;
    int i;

    // concat
    for (i = 0; i < 8; i++) {
        input[i] = a_pk[i];
        input[i + 8] = rho[i];
    }

    temp = sha2(input);
    for (i = 0; i < 12; i++) {
        input[i] = r[i];
    }
    for (i = 0; i < 4; i++) {
        input[i + 12] = temp.array[i];
    }

    return sha2(input);
}

struct Digest comm_s(uint32_t* k, uint64_t val) {
    uint32_t input[16];
    uint32_t paddedVal[8] = {0, 0, 0, 0, 0, 0, (uint32_t)(val >> 32), (uint32_t)val};
    int i;

    for (i = 0; i < 8; i++) {
        input[i] = k[i];
    }

    for (i = 0; i < 8; i++) {
        input[i + 8] = paddedVal[i];
    }

    return sha2(input);
}

void compute(struct In *input, struct Out *output) {
    // verifies that the commitments have appeared before on the ledger
    struct Digest merkleRoot;
    int i;

    merkleRoot = computeMerkleRoot(&(input->authPath1), &(input->c1_old_comm));
    for (i = 0; i < 8; i++) {
        assert_zero(merkleRoot.array[i] - input->root.array[i]);
    }

    merkleRoot = computeMerkleRoot(&(input->authPath2), &(input->c2_old_comm));
    for (i = 0; i < 8; i++) {
        assert_zero(merkleRoot.array[i] - input->root.array[i]);
    }

    // verifies the knowledge of the secret keys
    struct Digest prf;
    prf = prfAddr(input->sk1_old.array);
    for (i = 0; i < 8; i++) {
        assert_zero(prf.array[i] - input->c1_old.pubKey.array[i]);
    }

    prf = prfAddr(input->sk2_old.array);
    for (i = 0; i < 8; i++) {
        assert_zero(prf.array[i] - input->c2_old.pubKey.array[i]);
    }

    // compute old coins serial number
    output->sn1_old = prfSn(input->sk1_old.array, input->c1_old.rho);
    output->sn2_old = prfSn(input->sk2_old.array, input->c2_old.rho);

    // verify old commitments and compute the new ones
    struct Digest comm;
    comm = comm_s(comm_r(input->c1_old.rand, input->c1_old.pubKey.array, input->c1_old.rho).array, input->c1_old.value);
    for (i = 0; i < 8; i++) {
        assert_zero(comm.array[i] - input->c1_old_comm.array[i]);
    }

    comm = comm_s(comm_r(input->c2_old.rand, input->c2_old.pubKey.array, input->c2_old.rho).array, input->c2_old.value);
    for (i = 0; i < 8; i++) {
        assert_zero(comm.array[i] - input->c2_old_comm.array[i]);
    }

    output->c1_new_comm = comm_s(comm_r(input->c1_new.rand, input->c1_new.pubKey.array, input->c1_new.rho).array, input->c1_new.value);
    output->c2_new_comm = comm_s(comm_r(input->c2_new.rand, input->c2_new.pubKey.array, input->c2_new.rho).array, input->c2_new.value);

    // verify the correct flow of money
    assert_zero((input->c1_old.value + input->c2_old.value) - (input->c1_new.value + input->c2_new.value + input->pubVal));

    // hashes for non-malleability
    output->h1 = prfPk(input->sk1_old.array, input->h_sig.array);
    input->h_sig.array[0] = input->h_sig.array[0] | 0x80000000u;
    output->h2 = prfPk(input->sk2_old.array, input->h_sig.array);
}