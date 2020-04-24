#include "UnspentCalculator.h"

#include <iostream>

using namespace TW;
using namespace TW::Bitcoin;

UnspentCalculator UnspentCalculator::getCalculator(TWCoinType coinType) {
    switch (coinType) {
    case TWCoinTypeZelcash:
    case TWCoinTypeZcash: {
        auto calc = [](size_t inputs, size_t outputs, int64_t byteFee, char, int) -> int64_t { return 10000; };
        auto calcInput = [](int64_t byteFee) -> int64_t { return 0; };
        return UnspentCalculator(calc, calcInput);
    }
    case TWCoinTypeGroestlcoin: {
        auto calc = [](size_t inputs, size_t outputs, int64_t byteFee, char, int) -> int64_t { return 20000; };
        auto calcInput = [](int64_t byteFee) -> int64_t { return 0; };
        return UnspentCalculator(calc, calcInput);
    }
    case TWCoinTypeDecred: {
        auto calc = [](size_t inputs, size_t outputs, int64_t byteFee, char, int) -> int64_t { 
            const auto txsize = ((166 * inputs) + (38 * outputs) + 12);
            return int64_t(txsize) * byteFee;
        };
        auto calcInput = [](int64_t byteFee) -> int64_t { 
            return int64_t(166) * byteFee;
        };
        return UnspentCalculator(calc, calcInput);
    }
    default:
        return UnspentCalculator();
    }
}

int64_t UnspentCalculator::calculateFee(int64_t inputs, int64_t outputs, int64_t byteFee, char prefix, int witnessProgramSize) {
    const auto txsize = ((148 * inputs) + (34 * outputs) + 10);
    auto txsize2 = txsize;
    if (witnessProgramSize > 0) {
        txsize2 = txsize - (witnessProgramSize*3)/4;
    }
    std::cerr << "QQQ calculateFee " << witnessProgramSize << " " << prefix << " " << inputs << " " << outputs << " txsize " << txsize2 << " " << txsize << "\n";
    return int64_t(txsize) * byteFee;
}

int64_t UnspentCalculator::calculateSingleInputFee(int64_t byteFee) {
    return int64_t(148) * byteFee;
}
