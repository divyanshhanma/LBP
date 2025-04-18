#pragma once
#include "keys.hpp"
#include <vector>

void apply_mvb_lut(const std::vector<LweSample*>& inputs, LweSample* output, const TFHEKeys& keys);
