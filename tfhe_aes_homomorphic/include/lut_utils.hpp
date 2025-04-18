#pragma once
#include <tfhe/tfhe.h>
#include <tfhe_io.h>
#include "tree_lut.hpp"
#include <vector>

void trivial_encrypt(LweSample* out, int32_t value, const TFheGateBootstrappingSecretKeySet* key);
void trivial_decrypt(const LweSample* in, const TFheGateBootstrappingSecretKeySet* key, int32_t& out);
std::pair<TFheGateBootstrappingSecretKeySet*, const TFheGateBootstrappingCloudKeySet*> generate_keys();
std::vector<LweSample*> encrypt_byte(uint8_t byte, const TFheGateBootstrappingSecretKeySet* key);
uint8_t decrypt_byte(const std::vector<LweSample*>& encrypted, const TFheGateBootstrappingSecretKeySet* key);
std::vector<LweSample*> apply_lut_8bit_to_8bit(const std::vector<LweSample*>& input, const uint8_t lut[256], const TFheGateBootstrappingCloudKeySet* bk);
std::vector<LweSample*> mul_2(std::vector<LweSample*>& b,  TFheGateBootstrappingSecretKeySet* key);
std::vector<LweSample*> mul_3(std::vector<LweSample*>& b,  TFheGateBootstrappingSecretKeySet* key);
std::vector<LweSample*> mul_9(std::vector<LweSample*>& b,  TFheGateBootstrappingSecretKeySet* key);
std::vector<LweSample*> mul_b(std::vector<LweSample*>& b,  TFheGateBootstrappingSecretKeySet* key);
std::vector<LweSample*> mul_d(std::vector<LweSample*>& b,  TFheGateBootstrappingSecretKeySet* key);
std::vector<LweSample*> mul_e(std::vector<LweSample*>& b,  TFheGateBootstrappingSecretKeySet* key);
std::vector<LweSample*> eval_mul_T_a(const uint8_t table[256],  std::vector<LweSample*>& input_bits, TFheGateBootstrappingSecretKeySet* key);
void init_xor_lut_16x16();

LweSample* tree_based_lut_eval_bit(
    const std::vector<LweSample*>& selector,  // Encrypted 8-bit (a<<4|b)
    const uint8_t* lut,                       // 256-entry 1-bit LUT
    const TFheGateBootstrappingSecretKeySet* key);


std::vector<LweSample*> evaluate_4bit_xor_lut(
            const std::vector<LweSample*>& a,  // 4-bit encrypted (LSB first)
            const std::vector<LweSample*>& b,  // 4-bit encrypted (LSB first)
            const TFheGateBootstrappingSecretKeySet* key);

std::vector<LweSample*> homomorphic_xor_tree_based(
                const std::vector<LweSample*>& a,
                const std::vector<LweSample*>& b,
                TFheGateBootstrappingSecretKeySet* key);