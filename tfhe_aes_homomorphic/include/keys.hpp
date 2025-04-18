#pragma once
#include <tfhe.h>
#include <tfhe_io.h>

struct TFHEKeys {
    TFheGateBootstrappingParameterSet* params;
    TFheGateBootstrappingSecretKeySet* secretKey;
    const TFheGateBootstrappingCloudKeySet* cloudKey;

    TFHEKeys();
    ~TFHEKeys();
};
