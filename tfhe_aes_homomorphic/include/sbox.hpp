#pragma once
#include <tfhe/tfhe.h>
#include <vector>

std::vector<LweSample*> homomorphic_sbox(
    const std::vector<LweSample*>& input,
    const TFheGateBootstrappingCloudKeySet* bk);

    void sub_word(uint8_t* word);