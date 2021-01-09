/**************************************Library**************************************/
#include <BitBool.h>

/**************************************data handshake pins**************************************/
const byte modePin = 2; // attach to mode pin
const byte requestPin = 4; // attach to request pin
const byte getReadyPin = 3; // attach to Ready pin
const byte getInterruptPin = 5; // attach to valid pin
const byte dataPin[8]= {6, 7, 8, 9, 10, 11, 12, 13}; //attach to data pin 


/**************************************VARIABLES**************************************/
BitBool<8> puf[512] = {B0};
//BitBool<8> trng[512] = {B0};
BitBool<8> trng[51200] = {B0};

int stage = 0; 
const int PUF_DATA = 0;
const int TRNG_DATA = 1;
const int PRINT_DATA = 2;
const int AES_KEYEXP = 3;
const int AES_ENCRYPT = 4;
const int AES_DECRYPT = 5;
const int END = 6;

int count=0;
int num_temp=0;



/**************************************READ DATA FUNCTIONS**************************************/
//inline void wait_valid() __attribute__((always_inline));
void wait_valid(){
    // wait Valid == 1
    while(digitalRead(getInterruptPin)==LOW){
        delayMicroseconds(1);
    }
    
    //num_temp = 128*digitalRead(dataPin[7])+64*digitalRead(dataPin[6])+32*digitalRead(dataPin[5])+16*digitalRead(dataPin[4])+8*digitalRead(dataPin[3])+4*digitalRead(dataPin[2])+2*digitalRead(dataPin[1])+digitalRead(dataPin[0]);

    if(stage==PUF_DATA){
      for(int i=0;i<8;i++)
        puf[count][i] = digitalRead(dataPin[i]);
      count = count + 1;
    }else if(stage==TRNG_DATA){
      for(int i=0;i<8;i++)
        trng[count][i] = digitalRead(dataPin[i]);
      count = count + 1;
    }       
}

/**************************************BIT OPERATION FUNCTIONS**************************************/
const bool left = 0;
const bool right = 1;

uint32_t to_ulong_32(BitBool<32> in, int n_bits){
  uint32_t result = 0;
  for(int i=0;i<n_bits;i++){
    if(in[i]){
      result = result + pow(2,i);
    }
  }
  return result;
}

inline void to_ulong_8() __attribute__((always_inline));
uint32_t to_ulong_8(BitBool<8> in, int n_bits){
  uint32_t result = 0;
  for(int i=0;i<n_bits;i++){
    if(in[i]){
      result = result + pow(2,i);
    }
  }
  return result;
}

BitBool<32> shift_32(BitBool<32> in, bool direct/*0: left; 1:right*/, int n_bits, int n_shift){
  BitBool<32> result = {B0};
  if(direct==left){
    // shift left
      for(int i=0;i<n_bits-n_shift;i++){
        result[n_shift+i] = in[i];
      }
   }else{
    // right shift
      for(int i=0;i<n_bits-n_shift;i++){
        result[i]= in[n_shift+i];
      }
   }
  return result;
}

BitBool<8> shift_8(BitBool<8> in, bool direct/*0: left; 1:right*/, int n_bits, int n_shift){
  BitBool<8> result = {B0};
  if(direct==left){
    // shift left
      for(int i=0;i<n_bits-n_shift;i++){
        result[n_shift+i] = in[i];
      }
   }else{
    // right shift
      for(int i=0;i<n_bits-n_shift;i++){
        result[i]= in[n_shift+i];
      }
   }
  return result;
}




BitBool<32> Concat(BitBool<8> in_a, BitBool<8> in_b, BitBool<8> in_c, BitBool<8> in_d){
    BitBool<32> result = {B0};
    for(int i=0;i<32;i++){
      if(i<8) result[i] = in_d[i];
      else if(i<16) result[i] = in_c[i-8];
      else if(i<24) result[i] = in_b[i-16];
      else result[i] = in_a[i-24];
    }
    return result;
}

BitBool<32> XOR_32 (BitBool<32> in_a, BitBool<32> in_b){
   BitBool<32> result = {B0};
   for(int i=0;i<32;i++){
      result[i] = in_a[i] ^ in_b[i]; 
   }
   return result;
}

BitBool<8> XOR_8 (BitBool<8> in_a, BitBool<8> in_b){
   BitBool<8> result = {B0};
   for(int i=0;i<8;i++){
      result[i] = in_a[i] ^ in_b[i]; 
   }
   return result;
}

BitBool<8> XOR_8_in4 (BitBool<8> in_a, BitBool<8> in_b, BitBool<8> in_c, BitBool<8> in_d){
   BitBool<8> result = {B0};
   for(int i=0;i<8;i++){
      result[i] = in_a[i] ^ in_b[i] ^ in_c[i] ^in_d[i]; 
   }
   return result;
}



BitBool<32> OR (BitBool<32> in_a, BitBool<32> in_b){
   BitBool<32> result = {B0};
   for(int i=0;i<32;i++){
      result[i] = in_a[i] | in_b[i]; 
   }
   return result;
}


void print_BitBool_32(BitBool<32>in){
  for(int i=0;i<32;i++){
    Serial.print(in[31-i]);
  }
  Serial.print("\n");
}

/**************************************AES VARIABLES **************************************/
const int Nr = 10; // # of round   


BitBool<8> plain_text[16] = {0x00, 0x41, 0x55, 0xc3, 
                             0x01, 0x41, 0x67, 0xee,
                             0x11, 0x41, 0xaa, 0xfe,
                             0x21, 0x41, 0xef, 0xef};
                             
//                                                 // w0   w1   w2   w3                                            
// BitBool<8> key[16] = {0x00, 0x7d, 0x20, 0x44,   // k0   k4   k8   k12      
//                       0xaa, 0x1c, 0x50, 0x39,   // k1   k5   k9   k13
//                       0x03, 0x00, 0x6f, 0x22,   // k2   k6   k10  k14
//                       0x06, 0x03, 0x01, 0x0e};  // k3   k7   k11  k15
                
BitBool<8> key[16];

BitBool<8>  in[16];
BitBool<32> w[4*(Nr+1)];
BitBool<8> S_Box[16][16] = {
  {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
  {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
  {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
  {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
  {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
  {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
  {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
  {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
  {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
  {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
  {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
  {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
  {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
  {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
  {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
  {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};
  
BitBool<8> Inv_S_Box[16][16] = {
  {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
  {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
  {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
  {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
  {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
  {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
  {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
  {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
  {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
  {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
  {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
  {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
  {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
  {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
  {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
  {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};

  
// all zero... I guess they are too long to initialize..
//  BitBool<32> RCon[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 
//                        0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

// So, I only save the first two chars which can stand for the original RCon values.
BitBool<8> RCon_short[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 
                             0x20, 0x40, 0x80, 0x1b, 0x36};  
                                                




/**************************************AES: KEY EXPANSION FUNCTIONS**************************************/
BitBool<32> RotWord(BitBool<32>  w){
    BitBool<32> head = {B0};
    BitBool<32> tail = {B0};
    BitBool<32> RotWord_result = {B0};

    head = shift_32(w, right, 32, 24);
    tail = shift_32(w, left, 32, 8);
    RotWord_result = OR(head, tail);

    
    return RotWord_result;
}


BitBool<32> SubWord(BitBool<32> w){
    int row=0;
    int col=0;
    uint32_t s_box_val=0;
    BitBool<32> w_transform = {B0};
    
    for(int i=0; i<32; i=i+8){
        row = w[i+4] + w[i+5]*2 + w[i+6]*4 + w[i+7]*8;
        col = w[i] + w[i+1]*2 + w[i+2]*4 + w[i+3]*8;
        s_box_val = to_ulong_8(S_Box[row][col], 8);
        auto result = toBitBool(s_box_val);
        result = shift_32(result, left, 32, i);
        w_transform = OR(w_transform, result);

    }
    return w_transform;
}

void key_expansion(BitBool<8> key[], BitBool<32> w[]){ 
    BitBool<32> pre_w = {B0};
    BitBool<32> t = {B0};
    BitBool<32> RCon_origin = {B0};
    for(int i=0; i<4*(Nr+1); i++){
        if(i<4){
            w[i] = Concat(key[i], key[i+4], key[i+8], key[i+12]); //OK
        }else{
            pre_w = w[i-1];
            if(i % 4==0){
              // t FIRST ALREADY WRONG-> rCons are Zero WHY??
              // Sol way: 
              for(int j=0;j<8;j++)
                RCon_origin[24+j] = RCon_short[(i/4)-1][j]; 
              //  
              t = XOR_32(SubWord(RotWord(pre_w)), RCon_origin);
              w[i] = XOR_32(w[i-4], t);
            }else{
              w[i] = XOR_32(w[i-4], pre_w);
            }
        }
    }
}


/**************************************AES: ENCRYPT FUNCTIONS**************************************/
void AddRoundKey(BitBool<8> in[16], BitBool<32> round_key[4]){
    BitBool<8> key0, key1, key2, key3;
    for(int i=0; i<4; i++){
        for(int j=0; j<8; j++){
            key0[j] = round_key[i][j+24];
            key1[j] = round_key[i][j+16];
            key2[j] = round_key[i][j+8];
            key3[j] = round_key[i][j];
        }
        in[i] = XOR_8(in[i], key0);
        in[i+4] = XOR_8(in[i+4], key1);
        in[i+8] = XOR_8(in[i+8], key2);
        in[i+12] = XOR_8(in[i+12], key3);
    }
}

void SubBytes(BitBool<8>  in[16]){
    int row;
    int col;
    for(int i=0; i<16; i++){
        row = in[i][4] + in[i][5]*2 + in[i][6]*4 + in[i][7]*8;
        col = in[i][0] + in[i][1]*2 + in[i][2]*4 + in[i][3]*8;
        in[i] = S_Box[row][col];
    }
}

void ShiftRows(BitBool<8> in[16]){
    BitBool<8> temp;
    //for row 1: left shift 1 byte
    temp = in[4];
    for(int i=4; i<7; i++){
        in[i] = in[i+1];
    }
    in[7] = temp;

    //for row 2: left shift 2 bytes
    for(int i=8; i<10; i++){
        temp = in[i];
        in[i] = in[i+2];
        in[i+2] = temp;
    }

    //for row 3: left shift 3 bytes = right shift 1 byte
    temp = in[15];
    for(int i=15; i>12; i--){
        in[i] = in[i-1];
    }
    in[12] = temp;
}

BitBool<8> GFMul(BitBool<8> a, BitBool<8> b){
  BitBool<8> out = {B0};
  BitBool<8> correction = {0x1b};  /* x^8 + x^4 + x^3 + x + 1 */
  bool MSB;
  for (int i=0; i<8; i++){
    if(b[0] == 1){
      out = XOR_8(out, a);
    }
    MSB = a[7];
    a = shift_8(a, left, 8, 1);
    
    if (MSB == 1) {
      a = XOR_8(a, correction);
    }
    b = shift_8(b, right, 8, 1);
  }
  return out;
}

void MixColumns(BitBool<8> in[16]){
    BitBool<8> s0, s1, s2, s3;
    for(int i=0; i<4; i++){
        s0 = in[i];
        s1 = in[i+4];
        s2 = in[i+8];
        s3 = in[i+12];
        in[i] = XOR_8_in4(GFMul(s0, {0x02}), GFMul(s1, {0x03}), s2, s3);
        in[i+4] = XOR_8_in4(s0, GFMul(s1, {0x02}), GFMul(s2, {0x03}), s3);
        in[i+8] = XOR_8_in4(s0, s1, GFMul(s2, {0x02}), GFMul(s3, {0x03}));
        in[i+12] = XOR_8_in4(GFMul(s0, {0x03}), s1, s2, GFMul(s3, {0x02}));
    }
}

void encrypt(BitBool<8> in[], BitBool<32> w[]){
    BitBool<32> round_key[4]; 
    //initial round
    for(int i=0; i<4; i++){
        round_key[i] = w[i];
    }
    AddRoundKey(in, round_key);

    //9 main rounds
    for(int i=1; i<10; i++){
        SubBytes(in);
        ShiftRows(in);
        MixColumns(in);
        for(int j=0; j<4; j++){
            round_key[j] = w[4*i+j];
        }
        AddRoundKey(in, round_key);
    }

    //final round
    SubBytes(in);
    ShiftRows(in);
    for(int i=0; i<4; i++){
        round_key[i] = w[i+40];
    }
    AddRoundKey(in, round_key);
}

/**************************************AES: DECRYPT FUNCTIONS**************************************/
void InvShiftRows(BitBool<8> in[16]){
    BitBool<8> temp;
    //for row 1: right shift 1 byte
    temp = in[7];
    for(int i=7; i>4; i--){
        in[i] = in[i-1];
    }
    in[4] = temp;

    //for row 2: right shift 2 bytes = left shift 2 bytes
    for(int i=8; i<10; i++){
        temp = in[i];
        in[i] = in[i+2];
        in[i+2] = temp;
    }

    //for row 3: right shift 3 bytes = left shift 1 byte
    temp = in[12];
    for(int i=12; i<15; i++){
        in[i] = in[i+1];
    }
    in[15] = temp;
}

void InvSubBytes(BitBool<8> in[16]){
    int row;
    int col;
    for(int i=0; i<16; i++){
        row = in[i][4] + in[i][5]*2 + in[i][6]*4 + in[i][7]*8;
        col = in[i][0] + in[i][1]*2 + in[i][2]*4 + in[i][3]*8;
        in[i] = Inv_S_Box[row][col];
    }
}

void InvMixColumns(BitBool<8> in[16]){
    BitBool<8> s0, s1, s2, s3;
    for(int i=0; i<4; i++){
        s0 = in[i];
        s1 = in[i+4];
        s2 = in[i+8];
        s3 = in[i+12];
        in[i] = XOR_8_in4(GFMul(s0, {0x0e}), GFMul(s1, {0x0b}),  GFMul(s2, {0x0d}), GFMul(s3, {0x09}));
        in[i+4] = XOR_8_in4(GFMul(s0, {0x09}), GFMul(s1, {0x0e}),  GFMul(s2, {0x0b}), GFMul(s3, {0x0d}));
        in[i+8] = XOR_8_in4(GFMul(s0, {0x0d}), GFMul(s1, {0x09}),  GFMul(s2, {0x0e}), GFMul(s3, {0x0b}));
        in[i+12] = XOR_8_in4(GFMul(s0, {0x0b}), GFMul(s1, {0x0d}),  GFMul(s2, {0x09}), GFMul(s3, {0x0e}));
    }
}

void decrypt(BitBool<8> in[], BitBool<32> w[]){
    BitBool<32> round_key[4];
    //initial round
    for(int i=0; i<4; i++){
        round_key[i] = w[i+40];
    }
    AddRoundKey(in, round_key);

    //9 main rounds
    for(int i=9; i>0; i--){
        InvShiftRows(in);
        InvSubBytes(in);
        for(int j=0; j<4; j++){
            round_key[j] = w[4*i+j];
        }
        AddRoundKey(in, round_key);
        InvMixColumns(in);
    }

    //final round
    InvShiftRows(in);
    InvSubBytes(in);
    for(int i=0; i<4; i++){
        round_key[i] = w[i];
    }
    AddRoundKey(in, round_key);
}


  


/**************************************MAIN SETUP**************************************/
void setup() {
  // put your setup code here, to run once:
  /***set pin mode***/
  pinMode(modePin, OUTPUT);
  pinMode(requestPin, OUTPUT);
  pinMode(getReadyPin, INPUT);
  pinMode(getInterruptPin, INPUT);
  pinMode(dataPin[0], INPUT);
  pinMode(dataPin[1], INPUT);
  pinMode(dataPin[2], INPUT);
  pinMode(dataPin[3], INPUT);
  pinMode(dataPin[4], INPUT);
  pinMode(dataPin[5], INPUT);
  pinMode(dataPin[6], INPUT);
  pinMode(dataPin[7], INPUT);
  
  /***set baud rate***/
  Serial.begin(115200);
  
  /*** initialization ***/
  digitalWrite(requestPin, LOW); 
  digitalWrite(modePin, LOW); // PUF mode
  delay(1);
}





/**************************************MAIN LOOP**************************************/
void loop() {
  // put your main code here, to run repeatedly:
  if(stage==PUF_DATA){ //PUF stage
    if(count==512){
      stage = TRNG_DATA;
      count = 0;
      digitalWrite(modePin, HIGH);
      Serial.print("PRNG stage start"); 
      delay(0.1);
    }
    
    if(digitalRead(getReadyPin)==HIGH){
      // send a 1us request pulse
      digitalWrite(requestPin, HIGH);
      delayMicroseconds(1); 
      digitalWrite(requestPin, LOW);
      wait_valid();
    }
    
  }else if(stage==TRNG_DATA){ //TRNG stage
     if(count==51200){
        stage = PRINT_DATA;
        count = 0;
        delay(0.1);
     }
     
     if(digitalRead(getReadyPin)==HIGH){
      // send a 1us request pulse
      digitalWrite(requestPin, HIGH);
      delayMicroseconds(1); 
      digitalWrite(requestPin, LOW);
      wait_valid();

      }
  }else if(stage==PRINT_DATA){// print data 
//      Serial.print("\n===========================================\n");
//      Serial.print("\n\nTRNG data:\n");
//      for(int i=0;i<512;i++){
//        if(i%4==3){
//            if(to_ulong_8(trng[i], 8)<16) Serial.print("0");
//            Serial.println(to_ulong_8(trng[i], 8), HEX); 
//        }else{
//            if(i%4==0) {
//                Serial.print(i/4, DEC);
//                Serial.print(": ");
//            }
//            if(to_ulong_8(trng[i], 8)<16) Serial.print("0");
//            Serial.print(to_ulong_8(trng[i], 8), HEX); 
//        }
//      }
      for(int i=0;i<51200;i++){
        Serial.write((to_ulong_8(trng[i], 8)&0xFF));
        //Serial.write(trng[i]&0xFF);
      }
      count = 0;
      stage = TRNG_DATA;
//      delay(0.1);
     
  }else if(stage == AES_KEYEXP){
      
    //copy 128 bits (16bytes) of PUF data as key (equal to following equation)
    for(int i=0;i<16;i++){
        key[i] = puf[496+i];
    }

    //                w0         w1       w2        w3
    // key[16] = { puf[496], puf[497], puf[498], puf[499],
    //             puf[500], puf[501], puf[502], puf[503],
    //             puf[504], puf[505], puf[506], puf[507],
    //             puf[508], puf[509], puf[510], puf[511] };


    //print original key
    Serial.print("\n===========================================\n");
    Serial.println("\noriginal key:");
   
    for(int i=0; i<16; i++){
      if(i%4==3)
          Serial.println(to_ulong_8(key[i], 8),HEX);
      else{
          Serial.print(to_ulong_8(key[i], 8),HEX);
          Serial.print(" ");   
      }
    }


    key_expansion(key, w);
    Serial.print("\n===========================================\n");
    Serial.println("\nexpanded key:");
    for(int i=0; i<4*(Nr+1); i++){
        Serial.print("w[");
        Serial.print(i, DEC);
        Serial.print("] = ");
        Serial.println(to_ulong_32(w[i], 32), HEX);
    }

    //copy plain_text
    for(int i=0; i<16; i++){
        in[i] = plain_text[i];
    }

    //print plain_text
    Serial.print("\n===========================================\n");
    Serial.println("plain text:");
   
    for(int i=0; i<16; i++){
      if(i%4==3)
          Serial.println(to_ulong_8(in[i], 8),HEX);
      else{
          Serial.print(to_ulong_8(in[i], 8),HEX);
          Serial.print(" ");   
      }
    }

    stage = AES_ENCRYPT;
    delay(0.1);
  }else if(stage == AES_ENCRYPT){
    encrypt(in, w);    

    //print crypt_text
    Serial.print("\n===========================================\n");
    Serial.println("\ncrypt text:");
    for(int i=0; i<16; i++){
        if(i%4==3)
            Serial.println(to_ulong_8(in[i], 8),HEX);
        else{
            Serial.print(to_ulong_8(in[i], 8),HEX);
            Serial.print(" "); 
        }
    }

    stage = AES_DECRYPT;
    delay(0.1);
  }else if(stage == AES_DECRYPT){
    decrypt(in, w);

    //print decrypt_text
    Serial.print("\n===========================================\n");
    Serial.println("\ndecrypt text:");
    for(int i=0; i<16; i++){
        if(i%4==3)
            Serial.println(to_ulong_8(in[i], 8),HEX);
        else{
            Serial.print(to_ulong_8(in[i], 8),HEX);
            Serial.print(" ");   
        } 
    } 

    stage = END;
    delay(0.1);
  }else if(stage == END){

  }

}
