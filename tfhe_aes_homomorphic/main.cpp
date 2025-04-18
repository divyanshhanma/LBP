#include "keys.hpp"
#include "tree_lut.hpp"
#include "mvb_lut.hpp"
#include "lut_utils.hpp"
#include <iostream>
#include "sbox.hpp"
#include <chrono> 


void homomorphic_aes_encrypt(
    std::vector<std::vector<LweSample*>>& ciphertext_block,  // 16 x 8 encrypted bits
    const std::vector<std::vector<std::vector<LweSample*>>>& encrypted_keys,  // 11 round keys
    TFheGateBootstrappingSecretKeySet* key) {

        std::cout<<"hi"<<"\n";
    if (ciphertext_block.size() != 16 || encrypted_keys.size() != 11) {
        throw std::runtime_error("Invalid input size");
    }

    // Initial AddRoundKey
    std::cout<<"Initial AddRoundKey ... "<<"\n";
    for (int i = 0; i < 16; ++i) {
        ciphertext_block[i] = homomorphic_xor_tree_based(ciphertext_block[i], encrypted_keys[0][i], key);
    }

    // Rounds 1 to 9

    for (int round = 1; round <= 9; ++round) {
        std::cout<<"Round "<<round<<"\n";
        // SubBytes
        std::cout<<"Subbytes "<<round<<"\n";
        for (int i = 0; i < 16; ++i) {
            ciphertext_block[i] = homomorphic_sbox(ciphertext_block[i], &key->cloud);
        }

        // ShiftRows
        std::cout<<"ShiftRows "<<round<<"\n";
        std::vector<std::vector<LweSample*>> temp = ciphertext_block;
        for (int row = 1; row < 4; ++row) {
            for (int col = 0; col < 4; ++col) {
                ciphertext_block[4 * row + col] = temp[4 * row + ((col + row) % 4)];
            }
        }

        // MixColumns
        std::cout<<"MixColumns "<<round<<"\n";
        for (int col = 0; col < 4; ++col) {
            int base = col * 4;
            std::vector<LweSample*> a0 = ciphertext_block[base + 0] ;
            std::vector<LweSample*> a1 = ciphertext_block[base + 1] ;
            std::vector<LweSample*> a2 = ciphertext_block[base + 2] ;
            std::vector<LweSample*> a3 = ciphertext_block[base + 3] ;

            auto r0 = homomorphic_xor_tree_based(homomorphic_xor_tree_based(mul_2(a0, key), mul_3(a1, key), key),
                                                 homomorphic_xor_tree_based(a2, a3, key), key);
            auto r1 = homomorphic_xor_tree_based(homomorphic_xor_tree_based(mul_2(a1, key), mul_3(a2, key), key),
                                                 homomorphic_xor_tree_based(a0, a3, key), key);
            auto r2 = homomorphic_xor_tree_based(homomorphic_xor_tree_based(mul_2(a2, key), mul_3(a3, key), key),
                                                 homomorphic_xor_tree_based(a0, a1, key), key);
            auto r3 = homomorphic_xor_tree_based(homomorphic_xor_tree_based(mul_2(a3, key), mul_3(a0, key), key),
                                                 homomorphic_xor_tree_based(a1, a2, key), key);

            ciphertext_block[base + 0] = r0;
            ciphertext_block[base + 1] = r1;
            ciphertext_block[base + 2] = r2;
            ciphertext_block[base + 3] = r3;
        }

        // AddRoundKey
        std::cout<<"AddRoundKey "<<round<<"\n";
        for (int i = 0; i < 16; ++i) {
            ciphertext_block[i] = homomorphic_xor_tree_based(ciphertext_block[i], encrypted_keys[round][i], key);
        }
    }

    // Final Round (no MixColumns)
    std::cout<<"Final Round "<<"\n";
    for (int i = 0; i < 16; ++i) {
        ciphertext_block[i] = homomorphic_sbox(ciphertext_block[i], &key->cloud);
    }

    std::vector<std::vector<LweSample*>> temp = ciphertext_block;
    for (int row = 1; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            ciphertext_block[4 * row + col] = temp[4 * row + ((col + row) % 4)];
        }
    }

    for (int i = 0; i < 16; ++i) {
        ciphertext_block[i] = homomorphic_xor_tree_based(ciphertext_block[i], encrypted_keys[10][i], key);
    }
    return;
}


const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) * 0x1b);
}

void rot_word(uint8_t* word) {
    uint8_t tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}



std::vector<std::vector<uint8_t>> aes_key_expansion(const std::vector<uint8_t>& key) {
    std::vector<std::vector<uint8_t>> round_keys(11, std::vector<uint8_t>(16));
    for (int i = 0; i < 16; ++i) round_keys[0][i] = key[i];

    for (int i = 1; i <= 10; ++i) {
        uint8_t temp[4];
        for (int j = 0; j < 4; ++j) temp[j] = round_keys[i - 1][j + 12];

        rot_word(temp);
        sub_word(temp);
        temp[0] ^= Rcon[i];

        for (int j = 0; j < 16; ++j) {
            round_keys[i][j] = round_keys[i - 1][j] ^ (j < 4 ? temp[j] : round_keys[i][j - 4]);
        }
    }
    return round_keys;
}

std::vector<std::vector<LweSample*>> encrypt_round_key(    const std::vector<uint8_t>& round_key,    const TFheGateBootstrappingSecretKeySet* key) {

    const TFheGateBootstrappingParameterSet* params = key->params;

    std::vector<std::vector<LweSample*>> encrypted_key(16, std::vector<LweSample*>(8));
    
    for (int i = 0; i < 16; ++i) {
        uint8_t byte = round_key[i];
        for (int j = 0; j < 8; ++j) {
            encrypted_key[i][j] = new_LweSample(params->in_out_params);
            bootsSymEncrypt(encrypted_key[i][j], (byte >> j) & 1, key);
        }
    }

    return encrypted_key;
}


int main() {

    // 1. Key generation
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // 2. Define a 128-bit plaintext (example)
    uint8_t plaintext[16] = {0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37,
                             0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34};

    std::cout << "Original Plaintext Block:\n";
    for (int i = 0; i < 16; ++i)
        std::cout << std::hex << (int)plaintext[i] << " ";
    std::cout << "\n";

    // 3. Encrypt plaintext
    std::cout << "Encrypting plain text ... \n";
    std::vector<std::vector<LweSample*>> ciphertext_block;
    for (int i = 0; i < 16; ++i) {
        std::vector<LweSample*> enc_byte(8);
        for (int j = 0; j < 8; ++j) {
            enc_byte[j] = new_LweSample(params->in_out_params);
            bootsSymEncrypt(enc_byte[j], (plaintext[i] >> j) & 1, key);
        }
        ciphertext_block.push_back(enc_byte);
    }
    std::vector<uint8_t> base_key = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
    
    std::cout << "key expansion ... \n";
    auto round_keys = aes_key_expansion(base_key);
    std::vector<std::vector<std::vector<LweSample*>>> encrypted_keys;
    std::cout << "Encrypting keys ...  \n";
    for (const auto& round_key : round_keys) {
        encrypted_keys.push_back(encrypt_round_key(round_key, key));
    }

    // 5. Run homomorphic AES
    std::cout << "Running AES \n";
    auto start = std::chrono::high_resolution_clock::now();
      homomorphic_aes_encrypt(ciphertext_block, encrypted_keys, key);
    auto end = std::chrono::high_resolution_clock::now();
       
        std::chrono::duration<double> elapsed = end - start;
        


    // 6. Decrypt result
    std::cout << "Decrypting result ... \n";
    uint8_t decrypted_output[16];
    for (int i = 0; i < 16; ++i) {
        uint8_t byte = 0;
        for (int j = 0; j < 8; ++j) {
            int bit = bootsSymDecrypt(ciphertext_block[i][j], key);
            byte |= (bit << j);
        }
        decrypted_output[i] = byte;
    }

    std::cout << "Decrypted Ciphertext Block:\n";
    for (int i = 0; i < 16; ++i)
        std::cout << std::hex << (int)decrypted_output[i] << " ";
    std::cout << "\n";


    std::cout << "Time taken " << elapsed.count() << " seconds" << std::endl;

    // 7. Cleanup
    for (auto& byte : ciphertext_block)
        for (auto& bit : byte)
            delete_LweSample(bit);

    for (auto& byte : encrypted_keys)
        for (auto& bit : byte)
          for(auto& x: bit)
            delete_LweSample(x);

    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}


