// Ideally, we would use the crypto library for computing sha256 but, since we don't have a bundler in place yet and
// need to keep compatibility with older browsers, we temporarily use this implementation instead

class Sha256 {
  static hash(msg) {
      try {
        msg = new TextEncoder().encode(msg, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
      } catch (e) { // no TextEncoder available?
        msg = unescape(encodeURIComponent(msg)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
      }

      // constants
      const K = [
          0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ];

      // initial hash value
      const H = [
          0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ];

      // PREPROCESSING

      msg += String.fromCharCode(0x80);  // add trailing '1' bit (+ 0's padding) to string

      // convert string msg into 512-bit blocks (array of 16 32-bit integers)
      const l = msg.length/4 + 2; // length (in 32-bit integers) of msg + ‘1’ + appended length
      const N = Math.ceil(l/16);  // number of 16-integer (512-bit) blocks required to hold 'l' ints
      const M = new Array(N);     // message M is N×16 array of 32-bit integers

      for (let i=0; i<N; i++) {
          M[i] = new Array(16);
          for (let j=0; j<16; j++) { // encode 4 chars per integer (64 per block), big-endian encoding
              M[i][j] = (msg.charCodeAt(i*64+j*4+0)<<24) | (msg.charCodeAt(i*64+j*4+1)<<16)
                      | (msg.charCodeAt(i*64+j*4+2)<< 8) | (msg.charCodeAt(i*64+j*4+3)<< 0);
          } // note running off the end of msg is ok 'cos bitwise ops on NaN return 0
      }
      // add length (in bits) into final pair of 32-bit integers (big-endian)
      // note: most significant word would be (len-1)*8 >>> 32, but since JS converts
      // bitwise-op args to 32 bits, we need to simulate this by arithmetic operators
      const lenHi = ((msg.length-1)*8) / Math.pow(2, 32);
      const lenLo = ((msg.length-1)*8) >>> 0;
      M[N-1][14] = Math.floor(lenHi);
      M[N-1][15] = lenLo;


      // HASH COMPUTATION

      for (let i=0; i<N; i++) {
          const W = new Array(64);

          // 1 - prepare message schedule 'W'
          for (let t=0;  t<16; t++) {
            W[t] = M[i][t]
          };
          for (let t=16; t<64; t++) {
              W[t] = (sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]) >>> 0;
          }

          // 2 - initialise working variables a, b, c, d, e, f, g, h with previous hash value
          let a = H[0];
          let b = H[1];
          let c = H[2];
          let d = H[3];
          let e = H[4];
          let f = H[5];
          let g = H[6];
          let h = H[7];

          // 3 - main loop (note '>>> 0' for 'addition modulo 2^32')
          for (let t=0; t<64; t++) {
              const T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];
              const T2 =     SIGMA0(a) + Maj(a, b, c);
              h = g;
              g = f;
              f = e;
              e = (d + T1) >>> 0;
              d = c;
              c = b;
              b = a;
              a = (T1 + T2) >>> 0;
          }

          // 4 - compute the new intermediate hash value (note '>>> 0' for 'addition modulo 2^32')
          H[0] = (H[0]+a) >>> 0;
          H[1] = (H[1]+b) >>> 0;
          H[2] = (H[2]+c) >>> 0;
          H[3] = (H[3]+d) >>> 0;
          H[4] = (H[4]+e) >>> 0;
          H[5] = (H[5]+f) >>> 0;
          H[6] = (H[6]+g) >>> 0;
          H[7] = (H[7]+h) >>> 0;
      }

      // convert H0..H7 to hex strings (with leading zeros)
      for (let h=0; h<H.length; h++) {
        H[h] = ('00000000'+H[h].toString(16)).slice(-8)
      };

      return H.join('');
  }
}

function ROTR(n, x) {
  return (x >>> n) | (x << (32-n));
}

function SIGMA0(x) {
  return ROTR(2,  x) ^ ROTR(13, x) ^ ROTR(22, x);
}

function SIGMA1(x) {
  return ROTR(6,  x) ^ ROTR(11, x) ^ ROTR(25, x);
}

function sigma0(x) {
  return ROTR(7,  x) ^ ROTR(18, x) ^ (x>>>3);
}

function sigma1(x) {
  return ROTR(17, x) ^ ROTR(19, x) ^ (x>>>10);
}

function Ch(x, y, z) { // 'choice'
  return (x & y) ^ (~x & z);
}

function Maj(x, y, z) { // 'majority'
  return (x & y) ^ (x & z) ^ (y & z);
}

