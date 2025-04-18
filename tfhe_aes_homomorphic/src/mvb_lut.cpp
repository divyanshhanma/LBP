#include "mvb_lut.hpp"

void apply_mvb_lut(const std::vector<LweSample*>& inputs, LweSample* output, const TFHEKeys& keys) {
    // Placeholder: use the same as tree LUT for now
    bootsCOPY(output, inputs[0], keys.cloudKey);
    for (size_t i = 1; i < inputs.size(); ++i) {
        bootsXOR(output, output, inputs[i], keys.cloudKey);
    }
}
