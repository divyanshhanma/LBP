#include "tree_lut.hpp"
#include <functional>
#include <vector>


// LweSample* tree_based_lut_eval_bit(
//     const std::vector<LweSample*>& bits,  // Encrypted 8-bit input
//     const uint8_t* lut,                   // 256-entry 1-bit LUT
//     const TFheGateBootstrappingSecretKeySet* key) {

//     const TFheGateBootstrappingParameterSet* params = key->params;

//     // Leaf nodes: encrypt all 256 bits of LUT
//     std::vector<LweSample*> current_level(256);
//     for (int i = 0; i < 256; ++i) {
//         current_level[i] = new_LweSample(params->in_out_params);
//         bootsSymEncrypt(current_level[i], lut[i], key);
//     }

//     // Tree reduction: use bootsMUX over 8 bits
//     for (int level = 0; level < 8; ++level) {
//         std::vector<LweSample*> next_level(current_level.size() / 2);

//         for (size_t i = 0; i < next_level.size(); ++i) {
//             next_level[i] = new_LweSample(params->in_out_params);
//             bootsMUX(next_level[i], bits[7 - level], current_level[2 * i + 1], current_level[2 * i], &key->cloud);
//             delete_LweSample(current_level[2 * i]);
//             delete_LweSample(current_level[2 * i + 1]);
//         }

//         current_level = std::move(next_level);
//     }

//     // Only one result remains
//     return current_level[0];
// }


// Tree-based LUT Evaluation (TFHE-style)
std::vector<LweSample*> tree_based_lut_eval(const std::vector<LweSample*>& input, const uint8_t* lut, const TFheGateBootstrappingCloudKeySet* bk) {
    const int B = 2;                     // base for decomposition
    const int d = 8;                     // number of bits
    const int bit_size = 8;             // 8-bit output
    const TFheGateBootstrappingParameterSet* params = bk->params;
    
    std::vector<LweSample*> output_bits(bit_size);
    for (int i = 0; i < bit_size; ++i)
    output_bits[i] = new_gate_bootstrapping_ciphertext(params);
    
    // Recursive lambda to evaluate the LUT tree
    std::function<LweSample*(int bit, int left, int right, int depth)> eval_tree;
    
    eval_tree = [&](int out_bit, int left, int right, int depth) -> LweSample* {
    if (left + 1 == right) {
    int bit_val = (lut[left] >> out_bit) & 1;
    LweSample* ct = new_gate_bootstrapping_ciphertext(params);
    bootsCONSTANT(ct, bit_val, bk);
    return ct;
    }
    
    int mid = (left + right) / 2;
    LweSample* left_ct = eval_tree(out_bit, left, mid, depth + 1);
    LweSample* right_ct = eval_tree(out_bit, mid, right, depth + 1);
    
    LweSample* result = new_gate_bootstrapping_ciphertext(params);
    bootsMUX(result, input[d - depth - 1], right_ct, left_ct, bk);
    
    delete_gate_bootstrapping_ciphertext(left_ct);
    delete_gate_bootstrapping_ciphertext(right_ct);
    
    return result;
    };
    
    for (int bit = 0; bit < bit_size; ++bit) {
    LweSample* bit_result = eval_tree(bit, 0, 256, 0);
    bootsCOPY(output_bits[bit], bit_result, bk);
    delete_gate_bootstrapping_ciphertext(bit_result);
    }
    
    return output_bits;
    }