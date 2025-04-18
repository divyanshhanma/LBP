#include "keys.hpp"
#include <cstdlib>
#include <ctime>

TFHEKeys::TFHEKeys() {
    int minimum_lambda = 110;
    params = new_default_gate_bootstrapping_parameters(minimum_lambda);
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    secretKey = new_random_gate_bootstrapping_secret_keyset(params);
    cloudKey = &secretKey->cloud;
}

TFHEKeys::~TFHEKeys() {
    delete_gate_bootstrapping_secret_keyset(secretKey);
    delete_gate_bootstrapping_parameters(params);
}
