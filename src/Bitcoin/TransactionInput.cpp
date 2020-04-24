// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "TransactionInput.h"

#include "../BinaryCoding.h"

#include <iostream>

using namespace TW::Bitcoin;

void TransactionInput::encode(Data& data) const {
    auto& outpoint = reinterpret_cast<const TW::Bitcoin::OutPoint&>(previousOutput);
    outpoint.encode(data);
    script.encode(data);
    encode32LE(sequence, data);
}

void TransactionInput::encodeWitness(Data& data) const {
    int size1 = data.size();
    int wsize = 1;
    encodeVarInt(scriptWitness.size(), data);
    for (auto& item : scriptWitness) {
        encodeVarInt(item.size(), data);
        std::copy(std::begin(item), std::end(item), std::back_inserter(data));
        wsize += 1 + item.size();
    }
    int wsize2 = data.size() - size1;
    std::cerr << "QQQ encodeWitness " << scriptWitness.size() << " wsize " << wsize << " wsize2 " << wsize2 << "\n";
}
