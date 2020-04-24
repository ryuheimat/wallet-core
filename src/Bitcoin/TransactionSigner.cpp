// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "TransactionSigner.h"

#include "TransactionInput.h"
#include "TransactionOutput.h"
#include "UnspentSelector.h"

#include "../BinaryCoding.h"
#include "../Hash.h"
#include "../HexCoding.h"
#include "../Zcash/Transaction.h"
#include "../Groestlcoin/Transaction.h"

using namespace TW;
using namespace TW::Bitcoin;

template <typename Transaction, typename TransactionBuilder>
Result<Transaction> TransactionSigner<Transaction, TransactionBuilder>::sign() {
    signedInputs.clear();
    std::copy(std::begin(transaction.inputs), std::end(transaction.inputs),
              std::back_inserter(signedInputs));

    const bool hashSingle =
        ((input.hash_type() & ~TWBitcoinSigHashTypeAnyoneCanPay) == TWBitcoinSigHashTypeSingle);
    std::cerr << "QQQ TransactionSigner::sign() " << plan.utxos.size() << " " << hashSingle << " tx in out " << transaction.inputs.size() << " " << transaction.outputs.size() << "\n";
    for (auto i = 0; i < plan.utxos.size(); i += 1) {
        // Only sign TWBitcoinSigHashTypeSingle if there's a corresponding output
        if (hashSingle && i >= transaction.outputs.size()) {
            continue;
        }
        auto& utxo = plan.utxos[i];
        auto script = Script(utxo.script().begin(), utxo.script().end());
        auto result = sign(script, i, utxo);
        if (!result) {
            return Result<Transaction>::failure(result.error());
        }
    }

    Transaction tx(transaction);
    tx.inputs = move(signedInputs);
    tx.outputs = transaction.outputs;
    return Result<Transaction>::success(std::move(tx));
}

template <typename Transaction, typename TransactionBuilder>
int TransactionSigner<Transaction, TransactionBuilder>::witnessProgramSize(int output_size) {
    signedInputs.clear();
    std::copy(std::begin(transaction.inputs), std::end(transaction.inputs),
              std::back_inserter(signedInputs));
              
    const bool hashSingle =
        ((input.hash_type() & ~TWBitcoinSigHashTypeAnyoneCanPay) == TWBitcoinSigHashTypeSingle);
    std::cerr << "QQQ witnessProgramSize " << plan.utxos.size() << " " << hashSingle << " " << output_size << " tx in out " << transaction.inputs.size() << " " << transaction.outputs.size() << "\n";
    int sum = 0;
    for (auto i = 0; i < plan.utxos.size(); ++i) {
        // Only sign TWBitcoinSigHashTypeSingle if there's a corresponding output
        if (hashSingle && i >= output_size) {
            continue;
        }
        auto& utxo = input.utxo(i);
        auto script = Script(utxo.script().begin(), utxo.script().end());
        const auto size1 = witnessProgramSize(script, i, utxo);
        std::cerr << "   QQQ " << i << " " << utxo.script().size() << " " << size1 << " " << utxo.amount() << "\n";
        sum += size1;
    }
    std::cerr << "QQQ witnessProgramSize " << plan.utxos.size() << " res " << sum << "\n";
    return sum;
}

int totSize(const std::vector<Data>& dd) {
    int sum = 0;
    for (auto d: dd) sum += d.size();
    return sum;
}

template <typename Transaction, typename TransactionBuilder>
int TransactionSigner<Transaction, TransactionBuilder>::witnessProgramSize(const Script& script, size_t index, const Proto::UnspentTransaction& utxo) const {

    Script redeemScript;
    std::vector<Data> results;
    std::vector<Data> witnessStack;
    
    uint32_t signatureVersion = [this]() {
        if ((input.hash_type() & TWBitcoinSigHashTypeFork) != 0) {
            return WITNESS_V0;
        } else {
            return BASE;
        }
    }();
    
    auto result = signStep(script, index, utxo, signatureVersion); // TODO wrong
    if (!result) {
        return 0;
    } else {
        results = result.payload();
    }
 
    if (script.isPayToScriptHash()) {
        return 0;
    }

    Data data;
    if (script.matchPayToWitnessPublicKeyHash(data)) {
        auto witnessScript = Script::buildPayToPublicKeyHash(results[0]);
        //auto res = signStepSize(witnessScript);
        auto result = signStep(witnessScript, index, utxo, WITNESS_V0);
        if (!result) {
            return 0;
        }
        auto res = result.payload().size();
        std::cerr << "QQQ witnessProgramSize1 PayToWitnessPublicKeyHash " << res << "\n";
        return res;
    } else if (script.matchPayToWitnessScriptHash(data)) {
        auto witnessScript = Script(results[0].begin(), results[0].end());
        auto result = signStep(witnessScript, index, utxo, WITNESS_V0);
        std::vector<Data> witnessStack;    
        if (result) {
            witnessStack = result.payload();
        }
        witnessStack.push_back(move(witnessScript.bytes));
        //auto res = witnessScript.bytes.size() + signStepSize(witnessScript);
        auto res = totSize(witnessStack);
        std::cerr << "QQQ witnessProgramSize1 PayToWitnessScriptHash " << res << "\n";
        return res;
    }
    if (script.isWitnessProgram()) {
        // Error: Unrecognized witness program.
        assert(false);
        return 0;
    }
    return 0;
}

template <typename Transaction, typename TransactionBuilder>
int TransactionSigner<Transaction, TransactionBuilder>::signStepSize(const Script& script) const {
    std::cerr << "QQQ TransactionSigner::signStepSize " << script.bytes.size() << " " << hex(script.bytes) << "\n";
    Data data;
    if (script.matchPayToScriptHash(data)) {
        assert(false);
        /*
        auto redeemScript = scriptForScriptHash(data);
        if (redeemScript.empty()) {
            // Error: Missing redeem script
            return Result<std::vector<Data>>::failure("Missing redeem script.");
        }
        return Result<std::vector<Data>>::success({redeemScript});
        */
    }
    if (script.matchPayToWitnessScriptHash(data)) {
        auto scripthash = TW::Hash::ripemd(data);
        std::cerr << "   QQQ signStepSize PayToWitnessScriptHash hash " << hex(scripthash) << "\n";
        auto redeemScript = scriptForScriptHash(scripthash);
        if (redeemScript.empty()) {
            // Error: Missing redeem script
            return 0;
        }
        return redeemScript.size();
    }
    if (script.matchPayToWitnessPublicKeyHash(data)) {
        std::cerr << "   QQQ signStepSize PayToWitnessPublicKeyHash data " << hex(data) << "\n";
        return data.size();
    }
    if (script.isWitnessProgram()) {
        assert(false);
        //// Error: Invalid sutput script
        //return Result<std::vector<Data>>::failure("Invalid output script.");
    }
    std::vector<Data> keys;
    int required;
    if (script.matchMultisig(keys, required)) {
        assert(false);
        /*
        auto results = std::vector<Data>{{}}; // workaround CHECKMULTISIG bug
        for (auto& pubKey : keys) {
            if (results.size() >= required + 1) {
                break;
            }
            auto keyHash = TW::Hash::ripemd(TW::Hash::sha256(pubKey));
            auto key = keyForPublicKeyHash(keyHash);
            if (key.empty()) {
                // Error: missing key
                return Result<std::vector<Data>>::failure("Missing private key.");
            }
            auto signature =
                createSignature(transactionToSign, script, key, index, utxo.amount(), version);
            if (signature.empty()) {
                // Error: Failed to sign
                return Result<std::vector<Data>>::failure("Failed to sign.");
            }
            results.push_back(signature);
        }
        results.resize(required + 1);
        return Result<std::vector<Data>>::success(std::move(results));
        */
    }
    if (script.matchPayToPubkey(data)) {
        assert(false);
        /*
        auto keyHash = TW::Hash::ripemd(TW::Hash::sha256(data));
        auto key = keyForPublicKeyHash(keyHash);
        if (key.empty()) {
            // Error: Missing key
            return Result<std::vector<Data>>::failure("Missing private key.");
        }
        auto signature =
            createSignature(transactionToSign, script, key, index, utxo.amount(), version);
        if (signature.empty()) {
            // Error: Failed to sign
            return Result<std::vector<Data>>::failure("Failed to sign.");
        }
        return Result<std::vector<Data>>::success({signature});
        */
    }
    if (script.matchPayToPubkeyHash(data)) {
        auto key = keyForPublicKeyHash(data);
        std::cerr << "   QQQ signStepSize PayToPubkeyHash data " << hex(data) << " key " << hex(key) << "\n";
        if (key.empty()) {
            return 0;
        }
        return 71 + 65;
    }
    std::cerr << "   QQQ signStepSize ?? 0 \n";
    /*else {
        // Error: Invalid output script
        return Result<std::vector<Data>>::failure("Invalid output script.");
    }
    */
    return 0;
}

template <typename Transaction, typename TransactionBuilder>
Result<void> TransactionSigner<Transaction, TransactionBuilder>::sign(Script script, size_t index,
                                                  const Bitcoin::Proto::UnspentTransaction& utxo) {
    Script redeemScript;
    std::vector<Data> results;
    std::vector<Data> witnessStack;

    std::cerr << "   QQQ TransactionSigner::sign(3) idx " << index << " ss " << script.bytes.size() << "\n";
    uint32_t signatureVersion = [this]() {
        if ((input.hash_type() & TWBitcoinSigHashTypeFork) != 0) {
            return WITNESS_V0;
        } else {
            return BASE;
        }
    }();
    auto result = signStep(script, index, utxo, signatureVersion);
    if (result) {
        results = result.payload();
    } else {
        return Result<void>::failure(result.error());
    }
    auto txin = transaction.inputs[index];

    if (script.isPayToScriptHash()) {
        script = Script(results.front().begin(), results.front().end());
        auto result = signStep(script, index, utxo, signatureVersion);
        if (!result) {
            return Result<void>::failure(result.error());
        }
        results = result.payload();
        results.push_back(script.bytes);
        redeemScript = script;
    }

    Data data;
    if (script.matchPayToWitnessPublicKeyHash(data)) {
        auto witnessScript = Script::buildPayToPublicKeyHash(results[0]);
        auto result = signStep(witnessScript, index, utxo, WITNESS_V0);
        if (result) {
            witnessStack = result.payload();
        } else {
            witnessStack.clear();
        }
        results.clear();
        std::cerr << "   QQQ sign1 PayToWitnessPublicKeyHash " << totSize(witnessStack) << "\n";
    } else if (script.matchPayToWitnessScriptHash(data)) {
        auto witnessScript = Script(results[0].begin(), results[0].end());
        auto result = signStep(witnessScript, index, utxo, WITNESS_V0);
        if (result) {
            witnessStack = result.payload();
        } else {
            witnessStack.clear();
        }
        witnessStack.push_back(move(witnessScript.bytes));

        results.clear();
        std::cerr << "   QQQ sign1 PayToWitnessScriptHash " << totSize(witnessStack) << "\n";
    } else if (script.isWitnessProgram()) {
        // Error: Unrecognized witness program.
        return Result<void>::failure("Unrecognized witness program");
    }

    if (!redeemScript.bytes.empty()) {
        results.push_back(redeemScript.bytes);
    }

    signedInputs[index] =
        TransactionInput(txin.previousOutput, Script(pushAll(results)), txin.sequence);
    signedInputs[index].scriptWitness = witnessStack;
    return Result<void>::success();
}

template <typename Transaction, typename TransactionBuilder>
Result<std::vector<Data>> TransactionSigner<Transaction, TransactionBuilder>::signStep(
    Script script, size_t index, const Bitcoin::Proto::UnspentTransaction& utxo, uint32_t version) const {
    std::cerr << "QQQ TransactionSigner::signStep " << script.bytes.size() << " " << hex(script.bytes) << "\n";
    Transaction transactionToSign(transaction);
    transactionToSign.inputs = signedInputs;
    transactionToSign.outputs = transaction.outputs;

    Data data;
    std::vector<Data> keys;
    int required;

    if (script.matchPayToScriptHash(data)) {
        auto redeemScript = scriptForScriptHash(data);
        if (redeemScript.empty()) {
            // Error: Missing redeem script
            return Result<std::vector<Data>>::failure("Missing redeem script.");
        }
        std::cerr << "   QQQ signStep PayToScriptHash " << redeemScript.size() << "\n";
        return Result<std::vector<Data>>::success({redeemScript});
    } else if (script.matchPayToWitnessScriptHash(data)) {
        auto scripthash = TW::Hash::ripemd(data);
        auto redeemScript = scriptForScriptHash(scripthash);
        if (redeemScript.empty()) {
            // Error: Missing redeem script
            return Result<std::vector<Data>>::failure("Missing redeem script.");
        }
        std::cerr << "   QQQ signStep PayToWitnessScriptHash " << redeemScript.size() << "\n";
        return Result<std::vector<Data>>::success({redeemScript});
    } else if (script.matchPayToWitnessPublicKeyHash(data)) {
        std::cerr << "   QQQ signStep PayToWitnessPublicKeyHash " << data.size() << "\n";
        return Result<std::vector<Data>>::success({data});
    } else if (script.isWitnessProgram()) {
        // Error: Invalid sutput script
        return Result<std::vector<Data>>::failure("Invalid output script.");
    } else if (script.matchMultisig(keys, required)) {
        auto results = std::vector<Data>{{}}; // workaround CHECKMULTISIG bug
        for (auto& pubKey : keys) {
            if (results.size() >= required + 1) {
                break;
            }
            auto keyHash = TW::Hash::ripemd(TW::Hash::sha256(pubKey));
            auto key = keyForPublicKeyHash(keyHash);
            if (key.empty()) {
                // Error: missing key
                return Result<std::vector<Data>>::failure("Missing private key.");
            }
            auto signature =
                createSignature(transactionToSign, script, key, index, utxo.amount(), version);
            if (signature.empty()) {
                // Error: Failed to sign
                return Result<std::vector<Data>>::failure("Failed to sign.");
            }
            results.push_back(signature);
        }
        results.resize(required + 1);
        return Result<std::vector<Data>>::success(std::move(results));
    } else if (script.matchPayToPubkey(data)) {
        auto keyHash = TW::Hash::ripemd(TW::Hash::sha256(data));
        auto key = keyForPublicKeyHash(keyHash);
        if (key.empty()) {
            // Error: Missing key
            return Result<std::vector<Data>>::failure("Missing private key.");
        }
        auto signature =
            createSignature(transactionToSign, script, key, index, utxo.amount(), version);
        if (signature.empty()) {
            // Error: Failed to sign
            return Result<std::vector<Data>>::failure("Failed to sign.");
        }
        return Result<std::vector<Data>>::success({signature});
    } else if (script.matchPayToPubkeyHash(data)) {
        auto key = keyForPublicKeyHash(data);
        if (key.empty()) {
            // Error: Missing keys
            return Result<std::vector<Data>>::failure("Missing private key.");
        }

        auto pubkey = PrivateKey(key).getPublicKey(TWPublicKeyTypeSECP256k1);
        auto signature =
            createSignature(transactionToSign, script, key, index, utxo.amount(), version);
        if (signature.empty()) {
            // Error: Failed to sign
            return Result<std::vector<Data>>::failure("Failed to sign.");
        }
        return Result<std::vector<Data>>::success({signature, pubkey.bytes});
    } else {
        // Error: Invalid output script
        std::cerr << "   QQQ signStep Invalid output script \n";
        return Result<std::vector<Data>>::failure("Invalid output script.");
    }
}

template <typename Transaction, typename TransactionBuilder>
Data TransactionSigner<Transaction, TransactionBuilder>::createSignature(const Transaction& transaction,
                                                     const Script& script, const Data& key,
                                                     size_t index, Amount amount,
                                                     uint32_t version) const {
    auto sighash = transaction.getSignatureHash(script, index, static_cast<TWBitcoinSigHashType>(input.hash_type()), amount,
                                                static_cast<SignatureVersion>(version));
    auto pk = PrivateKey(key);
    auto sig = pk.signAsDER(Data(begin(sighash), end(sighash)), TWCurveSECP256k1);
    if (sig.empty()) {
        return {};
    }
    sig.push_back(static_cast<uint8_t>(input.hash_type()));
    return sig;
}

template <typename Transaction, typename TransactionBuilder>
Data TransactionSigner<Transaction, TransactionBuilder>::pushAll(const std::vector<Data>& results) {
    auto data = Data{};
    for (auto& result : results) {
        if (result.empty()) {
            data.push_back(OP_0);
        } else if (result.size() == 1 && result[0] >= 1 && result[0] <= 16) {
            data.push_back(Script::encodeNumber(result[0]));
        } else if (result.size() < OP_PUSHDATA1) {
            data.push_back(static_cast<uint8_t>(result.size()));
        } else if (result.size() <= 0xff) {
            data.push_back(OP_PUSHDATA1);
            data.push_back(static_cast<uint8_t>(result.size()));
        } else if (result.size() <= 0xffff) {
            data.push_back(OP_PUSHDATA2);
            encode16LE(static_cast<uint16_t>(result.size()), data);
        } else {
            data.push_back(OP_PUSHDATA4);
            encode32LE(static_cast<uint32_t>(result.size()), data);
        }
        std::copy(begin(result), end(result), back_inserter(data));
    }
    return data;
}

template <typename Transaction, typename TransactionBuilder>
Data TransactionSigner<Transaction, TransactionBuilder>::keyForPublicKeyHash(const Data& hash) const {
    for (auto& key : input.private_key()) {
        auto publicKey = PrivateKey(key).getPublicKey(TWPublicKeyTypeSECP256k1);
        auto keyHash = TW::Hash::ripemd(TW::Hash::sha256(publicKey.bytes));
        if (std::equal(std::begin(keyHash), std::end(keyHash), std::begin(hash), std::end(hash))) {
            return Data(key.begin(), key.end());
        }
    }
    return {};
}

template <typename Transaction, typename TransactionBuilder>
Data TransactionSigner<Transaction, TransactionBuilder>::scriptForScriptHash(const Data& hash) const {
    auto hashString = hex(hash.begin(), hash.end());
    auto it = input.scripts().find(hashString);
    if (it == input.scripts().end()) {
        // Error: Missing redeem script
        return {};
    }
    std::cerr << "QQQ TransactionSigner::scriptForScriptHash " << hash.size() << " " << it->second.size() << "\n";
    return Data(it->second.begin(), it->second.end());
}

// Explicitly instantiate a Signers for compatible transactions.
template class TW::Bitcoin::TransactionSigner<Bitcoin::Transaction, Bitcoin::TransactionBuilder>;
template class TW::Bitcoin::TransactionSigner<Zcash::Transaction, Zcash::TransactionBuilder>;
template class TW::Bitcoin::TransactionSigner<Groestlcoin::Transaction, Bitcoin::TransactionBuilder>;
