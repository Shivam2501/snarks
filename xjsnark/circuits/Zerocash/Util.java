package xjsnark.zerocash;

/*Generated by MPS */

import backend.auxTypes.UnsignedInteger;
import backend.structure.CircuitGenerator;

public class Util {

  public static final long[] K_CONST = {1116352408L, 1899447441L, 3049323471L, 3921009573L, 961987163L, 1508970993L, 2453635748L, 2870763221L, 3624381080L, 310598401L, 607225278L, 1426881987L, 1925078388L, 2162078206L, 2614888103L, 3248222580L, 3835390401L, 4022224774L, 264347078L, 604807628L, 770255983L, 1249150122L, 1555081692L, 1996064986L, 2554220882L, 2821834349L, 2952996808L, 3210313671L, 3336571891L, 3584528711L, 113926993L, 338241895L, 666307205L, 773529912L, 1294757372L, 1396182291L, 1695183700L, 1986661051L, 2177026350L, 2456956037L, 2730485921L, 2820302411L, 3259730800L, 3345764771L, 3516065817L, 3600352804L, 4094571909L, 275423344L, 430227734L, 506948616L, 659060556L, 883997877L, 958139571L, 1322822218L, 1537002063L, 1747873779L, 1955562222L, 2024104815L, 2227730452L, 2361852424L, 2428436474L, 2756734187L, 3204031479L, 3329325298L};
  public static final long[] H_CONST = {1779033703L, 3144134277L, 1013904242L, 2773480762L, 1359893119L, 2600822924L, 528734635L, 1541459225L};


  public static Digest sha2(UnsignedInteger[] input) {

    if (input.length != 16) {
      throw new IllegalArgumentException("This method only accepts 16 32-bit words as inputs");
    }

    UnsignedInteger[] H = UnsignedInteger.instantiateFrom(32, H_CONST);

    UnsignedInteger[] words = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{64}, 32);
    UnsignedInteger a = H[0].copy(32);
    UnsignedInteger b = H[1].copy(32);
    UnsignedInteger c = H[2].copy(32);
    UnsignedInteger d = H[3].copy(32);
    UnsignedInteger e = H[4].copy(32);
    UnsignedInteger f = H[5].copy(32);
    UnsignedInteger g = H[6].copy(32);
    UnsignedInteger h = H[7].copy(32);

    for (int j = 0; j < 16; j++) {
      
      words[j].assign(input[j], 32);;
    }

    for (int j = 16; j < 64; j++) {
      UnsignedInteger s0 = rotateRight(words[j - 15].copy(32), 7).xorBitwise(rotateRight(words[j - 15].copy(32), 18)).xorBitwise((words[j - 15].shiftRight(3))).copy(32);
      UnsignedInteger s1 = rotateRight(words[j - 2].copy(32), 17).xorBitwise(rotateRight(words[j - 2].copy(32), 19)).xorBitwise((words[j - 2].shiftRight(10))).copy(32);
      
      words[j].assign(words[j - 16].add(s0).add(words[j - 7]).add(s1), 32);;
    }

    for (int j = 0; j < 64; j++) {
      UnsignedInteger s0 = rotateRight(a.copy(32), 2).xorBitwise(rotateRight(a.copy(32), 13)).xorBitwise(rotateRight(a.copy(32), 22)).copy(32);
      UnsignedInteger maj = (a.andBitwise(b)).xorBitwise((a.andBitwise(c))).xorBitwise((b.andBitwise(c))).copy(32);
      UnsignedInteger t2 = s0.add(maj).copy(32);

      UnsignedInteger s1 = rotateRight(e.copy(32), 6).xorBitwise(rotateRight(e.copy(32), 11)).xorBitwise(rotateRight(e.copy(32), 25)).copy(32);
      UnsignedInteger ch = e.andBitwise(f).xorBitwise(e.invBits().andBitwise(g)).copy(32);
      // the uint_32(.) call is to convert from java type to xjsnark type 
      UnsignedInteger t1 = h.add(s1).add(ch).add(UnsignedInteger.instantiateFrom(32, K_CONST[j])).add(words[j]).copy(32);
      
      h.assign(g, 32);;
      
      g.assign(f, 32);;
      
      f.assign(e, 32);;
      
      e.assign(d.add(t1), 32);;
      
      d.assign(c, 32);;
      
      c.assign(b, 32);;
      
      b.assign(a, 32);;
      
      a.assign(t1.add(t2), 32);;
    }

    
    H[0].assign(H[0].add(a), 32);;
    
    H[1].assign(H[1].add(b), 32);;
    
    H[2].assign(H[2].add(c), 32);;
    
    H[3].assign(H[3].add(d), 32);;
    
    H[4].assign(H[4].add(e), 32);;
    
    H[5].assign(H[5].add(f), 32);;
    
    H[6].assign(H[6].add(g), 32);;
    
    H[7].assign(H[7].add(h), 32);;

    Digest out = new Digest();
    out.array = H;
    return out;

  }

  public static UnsignedInteger rotateRight(UnsignedInteger in, int r) {
    return (in.shiftRight(r)).orBitwise((in.shiftLeft((32 - r))));
  }

  public static UnsignedInteger[] concat(UnsignedInteger[] a1, int idx1, int l1, UnsignedInteger[] a2, int idx2, int l2) {
    UnsignedInteger[] res = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{l1 + l2}, 32);
    for (int i = 0; i < l1; i++) {
      
      res[i].assign(a1[i + idx1], 32);;
    }
    for (int i = 0; i < l2; i++) {
      
      res[i + l1].assign(a2[i + idx2], 32);;
    }
    return res;
  }

}
