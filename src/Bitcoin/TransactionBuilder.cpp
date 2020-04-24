// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "TransactionBuilder.h"
#include "TransactionSigner.h"

#include <algorithm>

namespace TW::Bitcoin {

TransactionPlan TransactionBuilder::plan(const Bitcoin::Proto::SigningInput& input) {
        auto plan = TransactionPlan();
        plan.amount = input.amount();

        auto output_size = 2; // output + change
        auto calculator =
            UnspentCalculator::getCalculator(static_cast<TWCoinType>(input.coin_type()));
        auto unspentSelector = UnspentSelector(calculator);
        if (input.use_max_amount() && UnspentSelector::sum(input.utxo()) == plan.amount) {
            output_size = 1; // no change
            Amount newAmount = 0;
            auto input_size = 0;

            for (auto utxo : input.utxo()) {
                if (utxo.amount() >
                    unspentSelector.calculator.calculateSingleInput(input.byte_fee())) {
                    input_size++;
                    newAmount += utxo.amount();
                }
            }

            plan.amount = newAmount - unspentSelector.calculator.calculate(input_size, output_size,
                                                                           input.byte_fee(), 'T', 0);
            plan.amount = std::max(Amount(0), plan.amount);
        }

        plan.utxos =
            unspentSelector.select(input.utxo(), plan.amount, input.byte_fee(), output_size);

        //auto plan2 = std::move(plan.proto());
        auto inputWithPlan = std::move(input);
        *inputWithPlan.mutable_plan() = plan.proto();
        auto signer = TransactionSigner<Transaction, TransactionBuilder>(std::move(inputWithPlan));
        int witnessSize = signer.witnessProgramSize(output_size);

        plan.availableAmount = UnspentSelector::sum(plan.utxos);

        plan.fee = std::min(plan.availableAmount,
            unspentSelector.calculator.calculate(plan.utxos.size(), output_size, input.byte_fee(), 'Y', witnessSize));
        assert(plan.fee >= 0 && plan.fee <= plan.availableAmount);
        if (input.use_max_amount()) {
            // max_amount case
            plan.amount = std::max(Amount(0), plan.availableAmount - plan.fee);
            assert(plan.amount >= 0 && plan.amount <= plan.availableAmount);
            plan.change = 0;
        } else {
            if (plan.amount > plan.availableAmount - plan.fee) {
                plan.amount = std::max(Amount(0), plan.availableAmount - plan.fee);
            }

            plan.change = plan.availableAmount - plan.amount - plan.fee;
        }
        assert(plan.amount + plan.change + plan.fee == plan.availableAmount);

        return plan;
}

} // namespace TW::Bitcoin
