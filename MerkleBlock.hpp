/*
 *  Copyright (c) (2023) SPHINX_ORG
 *  Authors:
 *    - (C kusuma) <thekoesoemo@gmail.com>
 *      GitHub: (https://github.com/chykusuma)
 *  Contributors:
 *    - (Contributor 1) <email1@example.com>
 *      Github: (https://github.com/yourgit)
 *    - (Contributor 2) <email2@example.com>
 *      Github: (https://github.com/yourgit)
 */


/////////////////////////////////////////////////////////////////////////////////////////////////////////
// The provided code appears to be a C++ implementation of a Merkle block in the SPHINX cryptographic scheme. Here is a detailed explanation of the code:

  // The code begins with several #include statements, importing necessary libraries and header files.

  // It defines some forward declarations for functions and classes that are used in the code.

  // Next, it declares the SPHINXMerkleBlock namespace, which encapsulates the implementation of the Merkle block.

  // Within the SPHINXMerkleBlock namespace, several nested namespaces and structs are defined to organize the code.

  // The MerkleBlock class is defined, which represents a Merkle block in the SPHINX scheme. It contains private member variables and several nested classes for constructing different parts of the Merkle tree.

  // The constructMerkleTree function is responsible for constructing the Merkle tree from a vector of signed transactions. It recursively divides the transactions into halves, hashes them together, and combines the resulting roots until a single root (the Merkle root) is obtained.

  // The verifyMerkleRoot function checks whether a provided Merkle root matches the calculated Merkle root based on a vector of signed transactions. It calls the buildMerkleRoot function to construct the Merkle root and then compares it with the provided root.

  // The hashTransactions function takes two transaction strings, concatenates them, and hashes the result using the SPHINX-256 hash function.

  // The buildMerkleRoot function constructs the Merkle root from a vector of transactions. It sequentially applies different constructions (Fors, Wots, Hypertree, and XMSS) to generate the Merkle root.

  // The sign function and verify function are responsible for signing and verifying SPHINX signatures, respectively.
  
  // The remaining functions (constructWotsTree, constructForsTree, constructHypertree, and constructXmss) are implementation details of the Merkle block construction process.

  // The code includes additional comments specifying placeholders for certain values and functions that need to be replaced with actual values or implementations.

  // Overall, the code provides a framework for constructing and verifying Merkle blocks in the SPHINX cryptographic scheme. However, certain implementation details and missing parts need to be addressed before the code can be used in a functional manner.

// This code provides an implementation of constructing and verifying Merkle trees using the SPHINCS+ cryptographic scheme.
/////////////////////////////////////////////////////////////////////////////////////////////////////////



#ifndef MERKLEBLOCK_HPP
#define MERKLEBLOCK_HPP

#pragma once

#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include "lib/Sphincs/include/fors.hpp"
#include "lib/Sphincs/include/wots.hpp"
#include "lib/Sphincs/include/xmss.hpp"
#include "lib/Sphincs/include/hashing.hpp"
#include "lib/Sphincs/include/hypertree.hpp"
#include "lib/Sphincs/include/address.hpp"

#include "Merkleblock_error.hpp"
#include "Hash.hpp"
#include "Block.hpp"
#include "Sign.hpp"


// Forward declarations
namespace SPHINXSign {
    bool verifySignature(const std::vector<uint8_t>& data, const std::string& signature, const SPHINXMerkleBlock::PublicKey& public_key);
}

namespace SPHINXBlock {
    class Block; // Forward declaration of Block class
}

namespace SPHINXMerkleBlock {
    // Define PublicKey and other necessary types used in the code
    struct PublicKey {};

    struct SignedTransaction {
        std::string transaction;
        std::vector<uint8_t> data;
        std::string signature;
        PublicKey public_key;
    };

    namespace SPHINXHash {
        // Replace the placeholder with the actual SPHINX-256 hash function call
        std::string SPHINX_256(const std::string& data) {
            // Call the SPHINX-256 hash function from the library
            std::string hash = SPHINXHash(data);

            return hash;
        }
    }

    namespace SPHINCS {
        // Define the required functions used in the code
        namespace sphincs_adrs {
            struct fors_tree_t {};
        }

        namespace sphincs_fors {
            template <size_t n, uint32_t a, uint32_t k, typename T>
            void pkgen(const uint8_t* sk_seed, const uint8_t* pk_seed, const sphincs_adrs::fors_tree_t& adrs, T* pkey);
        }

        namespace sphincs_hashing {
            enum class variant {};

            template <size_t output_size, typename T>
            void h(const uint8_t* pk_seed, const sphincs_adrs::fors_tree_t& adrs, const char* message, T* output);
        }
    }

    class MerkleBlock {
        // Declare Block class as a friend
        friend class SPHINXBlock::Block;

        class ForsConstruction { // Define ForsConstruction class
        public:
            std::vector<std::string> constructForsTree(const std::vector<std::string>& transactions) const;
        };

        class WotsConstruction { // Define WotsConstruction class
        public:
            std::vector<std::string> constructWotsTree(const std::vector<std::string>& roots) const;
        };

        class HypertreeConstruction { // Define HypertreeConstruction class
        public:
            std::string constructHypertree(const std::vector<std::string>& roots) const;
        };

        class XmssConstruction { // Define XmssConstruction class
        public:
            std::string pkgen(const std::string& sk_seed, const std::string& pk_seed, std::string& pkey) const;
            std::string constructXMSS(const std::string& hypertreeRoot) const;
        };

    public:
        std::string constructMerkleTree(const std::vector<SignedTransaction>& signedTransactions) const;
        bool verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& transactions) const;

    private:
        std::string hashTransactions(const std::string& transaction1, const std::string& transaction2) const;
        std::string buildMerkleRoot(const std::vector<std::string>& transactions) const;
        bool sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk_seed, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, std::vector<uint8_t>& sig) const;
        bool verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, const std::vector<uint8_t>& pkey) const;

        ForsConstruction forsConstruction; // Add ForsConstruction instance
        WotsConstruction wotsConstruction; // Add WotsConstruction instance
        HypertreeConstruction hypertreeConstruction; // Add HypertreeConstruction instance
        XmssConstruction xmssConstruction; // Add XmssConstruction instance
    };

    std::string MerkleBlock::constructMerkleTree(const std::vector<SignedTransaction>& signedTransactions) const {
    // Base case: If there are no signed transactions, return an empty string
    if (signedTransactions.empty()) {
        return "";
    }

    // Base case: If there is only one signed transaction, return its hash as the Merkle tree root
    if (signedTransactions.size() == 1) {
        return SPHINXMerkleBlock::SPHINXHash::SPHINX_256(signedTransactions[0].transaction);
    }

    // Recursive case: Divide the signed transactions into two halves
    size_t mid = signedTransactions.size() / 2;
    std::vector<SignedTransaction> leftTransactions(signedTransactions.begin(), signedTransactions.begin() + mid);
    std::vector<SignedTransaction> rightTransactions(signedTransactions.begin() + mid, signedTransactions.end());

    // Recursively construct the Merkle tree for the left and right subtrees
    std::string leftRoot = constructMerkleTree(leftTransactions);
    std::string rightRoot = constructMerkleTree(rightTransactions);

    // Combine the left and right roots by hashing them together
    return SPHINXMerkleBlock::SPHINXHash::SPHINX_256(leftRoot + rightRoot);
}

bool MerkleBlock::verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& transactions) const {
    // Base case: If there are no transactions, the Merkle root should be an empty string
    if (transactions.empty()) {
        return merkleRoot.empty();
    }

    // Calculate the constructed Merkle root using the transactions
    std::string constructedRoot = buildMerkleRoot(transactions);

    // Compare the constructed Merkle root with the provided Merkle root
    return (constructedRoot == merkleRoot);
    }

    std::string MerkleBlock::hashTransactions(const std::string& transaction1, const std::string& transaction2) const {
        // Concatenate the two transactions and compute their hash using the SPHINX_256 hash function
        return SPHINXMerkleBlock::SPHINXHash::SPHINX_256(transaction1 + transaction2);
    }

    std::string MerkleBlock::buildMerkleRoot(const std::vector<std::string>& transactions) const {
        // Base case: If there are no transactions, return an empty string
        if (transactions.empty()) {
            return "";
        }

        // Base case: If there is only one transaction, return its hash as the Merkle root
        if (transactions.size() == 1) {
            return SPHINXMerkleBlock::SPHINXHash::SPHINX_256(transactions[0]);
        }

        // Recursive case: Divide the transactions into two halves
        size_t mid = transactions.size() / 2;
        std::vector<std::string> leftTransactions(transactions.begin(), transactions.begin() + mid);
        std::vector<std::string> rightTransactions(transactions.begin() + mid, transactions.end());

        // Recursively build the Merkle root for the left and right subtrees
        std::string leftRoot = buildMerkleRoot(leftTransactions);
        std::string rightRoot = buildMerkleRoot(rightTransactions);

        // Combine the left and right roots by hashing them together
        return SPHINXMerkleBlock::SPHINXHash::SPHINX_256(leftRoot + rightRoot);
    }

    bool MerkleBlock::sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk_seed, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, std::vector<uint8_t>& sig) const {
        constexpr uint32_t h = /* specify the value of h */; // Replace with actual value
        constexpr uint32_t d = /* specify the value of d */; // Replace with actual value
        constexpr size_t n = /* specify the value of n */; // Replace with actual value
        constexpr size_t w = /* specify the value of w */; // Replace with actual value
        constexpr sphincs_hashing::variant v = /* specify the variant */; // Replace with actual value

        sphincs_ht::sign<h, d, n, w, v>(sk_seed.data(), pk_seed.data(), idx_tree, idx_leaf, sig.data());
        return true; // Return appropriate success/failure value
    }

    bool MerkleBlock::verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, const std::vector<uint8_t>& pkey) const {
        constexpr uint32_t h = /* specify the value of h */; // Replace with actual value
        constexpr uint32_t d = /* specify the value of d */; // Replace with actual value
        constexpr size_t n = /* specify the value of n */; // Replace with actual value
        constexpr size_t w = /* specify the value of w */; // Replace with actual value
        constexpr sphincs_hashing::variant v = /* specify the variant */; // Replace with actual value

        return sphincs_ht::verify<h, d, n, w, v>(msg.data(), sig.data(), pk_seed.data(), idx_tree, idx_leaf, pkey.data());
    }

    std::vector<std::string> MerkleBlock::constructWotsTree(const std::vector<std::string>& roots) const {
        std::vector<std::string> wotsTree;
        
        for (const auto& root : roots) {
            std::array<uint8_t, n> message;
            // Assuming we have access to the necessary parameters (e.g., skSeed, pkSeed, adrs)
            // to generate a WOTS+ signature using the sign function from "WOTS.hpp"
            sphincs_wots::sign<n, w, v>(reinterpret_cast<const uint8_t*>(root.data()), skSeed.data(), pkSeed.data(), adrs, message.data());
            
            std::string wotsSignature(reinterpret_cast<const char*>(message.data()), n);
            wotsTree.push_back(wotsSignature);
        }
        
        return wotsTree;
    }

    std::vector<std::string> MerkleBlock::constructForsTree(const std::vector<std::string>& transactions) const {
        // Convert transactions to bytes (assuming they are already encoded)
        std::vector<uint8_t> transactionBytes;
        for (const auto& transaction : transactions) {
            transactionBytes.insert(transactionBytes.end(), transaction.begin(), transaction.end());
        }

        // Set the necessary parameters
        constexpr size_t n = /* specify the value for n */;
        constexpr uint32_t a = /* specify the value for a */;
        constexpr uint32_t k = /* specify the value for k */;
        constexpr sphincs_hashing::variant v = /* specify the variant */;

        // Generate the FORS public key
        uint8_t pk[n];
        sphincs_fors::pkgen<n, a, k, v>(nullptr, nullptr, sphincs_adrs::fors_tree_t(), pk);

        // Convert the public key to a string (assuming we want to return it as a string)
        std::string pkString(pk, pk + n);

        // Return the FORS public key
        return {pkString};
    }

    std::string HypertreeConstruction::constructHypertree(const std::vector<std::string>& roots) const {
        constexpr uint32_t h = /* specify the value of h */;
        constexpr uint32_t d = /* specify the value of d */;
        constexpr size_t n = /* specify the value of n */;
        constexpr size_t w = /* specify the value of w */;
        constexpr sphincs_hashing::variant v = /* specify the variant */;

        std::string skSeed = /* generate or retrieve the secret key seed */;
        std::string pkSeed = /* generate or retrieve the public key seed */;

        std::string hypertreeRoot(n, '\0');
        sphincs_ht::pkgen<h, d, n, w, v>(reinterpret_cast<const uint8_t*>(skSeed.data()), reinterpret_cast<const uint8_t*>(pkSeed.data()), reinterpret_cast<uint8_t*>(hypertreeRoot.data()));

        // Use the generated hypertreeRoot and roots to construct the Hypertree
        // ...

        return hypertreeRoot;
    }

    std::string constructXmss(const std::vector<std::string>& roots) const {
        constexpr uint32_t h = /* specify the value of h */;
        constexpr uint32_t d = /* specify the value of d */;
        constexpr size_t n = /* specify the value of n */;
        constexpr size_t w = /* specify the value of w */;
        constexpr sphincs_hashing::variant v = /* specify the variant */;

        sphincs_ht::pkgen<h, d, n, w, v>(reinterpret_cast<const uint8_t*>(sk_seed.data()), reinterpret_cast<const uint8_t*>(pk_seed.data()), reinterpret_cast<uint8_t*>(pkey.data()));
        return pkey;
    }

    bool MerkleBlock::verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& signedTransactions) const {
    std::vector<std::string> transactionList;
    for (const SignedTransaction& signedTransaction : signedTransactions) {
        // Verify the signature of the signed transaction using the verifySignature function from SPHINXSign namespace
        if (SPHINXSign::verifySignature(signedTransaction.data, signedTransaction.signature, signedTransaction.public_key)) {
            transactionList.push_back(signedTransaction.transaction);
        } else {
            // Handle invalid signature
            std::cerr << "ERROR: Invalid signature for transaction: " << signedTransaction.transaction << std::endl;
            return false;
        }
    }

    std::vector<std::string> merkleTree = transactionList;

    while (merkleTree.size() > 1) {
        std::vector<std::string> newMerkleTree;

        // Hash pairs of transactions
        for (size_t i = 0; i < merkleTree.size(); i += 2) {
            std::string transaction1 = merkleTree[i];
            std::string transaction2 = (i + 1 < merkleTree.size()) ? merkleTree[i + 1] : merkleTree[i];

            std::string hashedTransaction = hashTransactions(transaction1, transaction2);
            newMerkleTree.push_back(hashedTransaction);
        }

        merkleTree = newMerkleTree;
    }

    // Return the Merkle root hash
    std::string calculatedMerkleRoot = (merkleTree.empty()) ? "" : merkleTree[0];

        return (calculatedMerkleRoot == merkleRoot);
    }


    std::string MerkleBlock::hashTransactions(const std::string& transaction1, const std::string& transaction2) const {
        // Combine and hash two transactions using the SHAKE256 hash function from SPHINCS+
        std::string concatenatedTransactions = transaction1 + transaction2;

        constexpr size_t n = 32; // specify the required size
        constexpr uint32_t a = 1; // specify the required value
        constexpr uint32_t k = 1; // specify the required value
        constexpr SPHINCS::sphincs_hashing::variant v = SPHINCS::sphincs_hashing::variant{}; // specify the required variant

        // Initialize sk_seed and pk_seed with actual secret key seed and public key seed
        std::array<uint8_t, n> sk_seed = {}; // n-bytes secret key seed
        std::array<uint8_t, n> pk_seed = {}; // n-bytes public key seed

        SPHINCS::sphincs_adrs::fors_tree_t adrs{}; // 32-bytes FORS address

        std::array<uint8_t, n * a * k> pkey = {};
        SPHINCS::sphincs_fors::pkgen<n, a, k>(sk_seed.data(), pk_seed.data(), adrs, pkey.data());

        constexpr unsigned short hashbitlen = 256;
        std::array<uint8_t, hashbitlen / 8> merkleRoot;
        SPHINCS::sphincs_hashing::h<hashbitlen / 8>(pk_seed.data(), adrs, concatenatedTransactions.c_str(), merkleRoot.data());

        // Finalize the hash using SPHINXHash::SPHINX_256
        std::string finalizedMerkleRoot = SPHINXMerkleBlock::SPHINXHash::SPHINX_256(std::string(reinterpret_cast<const char*>(merkleRoot.data()), hashbitlen / 8));

        return finalizedMerkleRoot;
    }

    std::string MerkleBlock::buildMerkleRoot(const std::vector<std::string>& transactions) const {
        ForsConstruction forsConstruction;
        WotsConstruction wotsConstruction;
        HypertreeConstruction hypertreeConstruction;
        XmssConstruction xmssConstruction;

        // Construct the Merkle tree using Fors, Wots, Hypertree, and XMSS constructions

        // First, apply Fors construction on the transactions
        std::vector<std::string> forsRoots = forsConstruction.constructForsTree(transactions);

        // Next, apply Wots construction on the Fors roots
        std::vector<std::string> wotsRoots = wotsConstruction.constructWotsTree(forsRoots);

        // Then, apply Hypertree construction on the Wots roots
        std::string hypertreeRoot = hypertreeConstruction.constructHypertree(wotsRoots);

        // Finally, apply XMSS construction on the Hypertree root to obtain the Merkle root
        std::string merkleRoot = xmssConstruction.constructXMSS(hypertreeRoot);

        // Return the Merkle root hash
        return merkleRoot;
    }

} // namespace SPHINXMerkleBlock

#endif // MERKLEBLOCK_HPP
