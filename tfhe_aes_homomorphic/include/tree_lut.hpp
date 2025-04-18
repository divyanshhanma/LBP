#pragma once
#include "keys.hpp"
#include <vector>


// LweSample* tree_based_lut_eval_bit(
//     const std::vector<LweSample*>& bits,  // Encrypted 8-bit input
//     const uint8_t* lut,                   // 256-entry 1-bit LUT
//     const TFheGateBootstrappingSecretKeySet* key);
std::vector<LweSample*> tree_based_lut_eval(const std::vector<LweSample*>& input, const uint8_t* lut, const TFheGateBootstrappingCloudKeySet* bk);