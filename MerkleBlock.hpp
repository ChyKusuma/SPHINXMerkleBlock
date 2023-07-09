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
// The provided code is an implementation of the SPHINCS+ Merkle Trees scheme. Let's break down the code and explain its components in detail:

// Namespaces:
  // SPHINXSign: Contains the verifySignature function used for verifying signatures.
  // SPHINXBlock: Contains the forward declaration of the Block class.
  // SPHINXMerkleBlock: Contains the implementation of the SPHINCS+ Merkle Trees scheme.

// struct PublicKey:
  // Represents the public key used in the scheme.

// struct SignedTransaction:
  // Contains the necessary data for a signed transaction.
  // Includes the transaction itself, the associated data, the signature, and the public key.

// namespace SPHINXHash:
  // Contains the SPHINX_256 function, which computes the SPHINX-256 hash of a given input data using the sphinx256_hash function from the library.

// namespace SPHINCS:
  // Contains several nested namespaces related to the SPHINCS (SPHINCS+) construction.

// class MerkleBlock:
  // Implements the core functionality of the SPHINCS+ Merkle Trees scheme.
  // It consists of several private and public member functions to construct and verify the Merkle tree.

// Key Member Functions:
  // constructMerkleTree: Recursively constructs the Merkle tree for a given list of signed transactions.
  // verifyMerkleRoot: Verifies if a provided Merkle root matches the constructed Merkle root from a given list of signed transactions.

// Helper Functions:
  // hashTransactions: Hashes two transactions using the SPHINX-256 hash function.
  // buildMerkleRoot: Builds the Merkle root by applying Fors, Wots, Hypertree, and XMSS constructions on the transactions.

// Construction Classes:
  // ForsConstruction: Implements the construction of the FORS (Forward-Randomized Structure) tree.
  // WotsConstruction: Implements the construction of the WOTS (Winternitz One-Time Signature) tree.
  // HypertreeConstruction: Implements the construction of the Hypertree.
  // XmssConstruction: Implements the construction of the XMSS (Extended Merkle Signature Scheme) tree.

// Private Member Variables:
  // Instances of the construction classes used to construct the Merkle tree.

// Implementation Details:
  // The code includes helper functions, such as sign and verify, which are not fully implemented but provide a skeleton for incorporating the signing and verification functionality.
  // Some functions, such as constructWotsTree, constructForsTree, constructHypertree, and constructXMSS, have placeholder implementations and may require additional parameters or modifications to work correctly.

// The code provides a framework for constructing and verifying a Merkle tree using the SPHINCS+ scheme. Some parts of the implementation is still incomplete and may need further development to function properly.
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
#include "Utils.hpp"


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
        std::string SPHINX_256(const std::string& data) {
            // Call the SPHINX-256 hash function from the library
            std::string hash = sphinx256_hash(data);
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
        // Define the necessary parameters for signing
        constexpr uint32_t h = 128; // Security parameter related to the hash function
        constexpr uint32_t d = 16;  // Number of layers in the hash tree
        constexpr size_t n = 32;    // Size of the hash output in bytes
        constexpr size_t w = 64;    // Winternitz parameter for the WOTS+ construction
        constexpr sphincs_hashing::variant v = sphincs_hashing::variant::SHA3_256;  // Variant of the hash function (SHA3-256)

        // Call the signing function from the SPHINCS library
        sphincs_ht::sign<h, d, n, w, v>(sk_seed.data(), pk_seed.data(), idx_tree, idx_leaf, sig.data());

        // Return an appropriate success/failure value
        return true;
    }

    bool MerkleBlock::verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, const std::vector<uint8_t>& pkey) const {
        // Define the necessary parameters for verification
        constexpr uint32_t h = 128; // Security parameter related to the hash function
        constexpr uint32_t d = 16;  // Number of layers in the hash tree
        constexpr size_t n = 32;    // Size of the hash output in bytes
        constexpr size_t w = 64;    // Winternitz parameter for the WOTS+ construction
        constexpr sphincs_hashing::variant v = sphincs_hashing::variant::SHA3_256;  // Variant of the hash function (SHA3-256)

        // Call the verification function from the SPHINCS library
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

        // Set the necessary parameters for FORS construction
        constexpr size_t n = 32;    // Size of the hash output in bytes
        constexpr uint32_t a = 32;  // Size of the message digest
        constexpr uint32_t k = 8;   // Number of iterations of the Winternitz algorithm
        constexpr sphincs_hashing::variant v = sphincs_hashing::variant::SHA3_256;  // Variant of the hash function (SHA3-256)

        // Generate the FORS public key using the provided parameters
        uint8_t pk[n];
        sphincs_fors::pkgen<n, a, k, v>(nullptr, nullptr, sphincs_adrs::fors_tree_t(), pk);

        // Convert the public key to a string (assuming we want to return it as a string)
        std::string pkString(pk, pk + n);

        // Return the FORS public key as a vector of strings
        return {pkString};
    }

    std::string MerkleBlock::constructHypertree(const std::vector<std::string>& roots) const {
        // Set the necessary parameters for Hypertree construction
        constexpr uint32_t h = 128;   // Height of the binary tree
        constexpr uint32_t d = 16;    // Number of layers in the binary tree
        constexpr size_t n = 32;      // Size of the hash output in bytes (SHA3-256)
        constexpr size_t w = 64;      // Winternitz parameter
        constexpr sphincs_hashing::variant v = sphincs_hashing::variant::SHA3_256;  // Variant of the hash function (SHA3-256)

        // Generate or retrieve the secret key seed for Hypertree
        std::string skSeed = SPHINXUtils::generateOrRetrieveSecretKeySeed();

        // Generate or retrieve the public key seed for Hypertree
        std::string pkSeed = SPHINXUtils::generateOrRetrievePublicKeySeed();

        // Create a string to store the Hypertree root
        std::string hypertreeRoot(n, '\0');

        // Generate the Hypertree root using the provided parameters and seeds
        sphincs_ht::pkgen<h, d, n, w, v>(reinterpret_cast<const uint8_t*>(skSeed.data()), reinterpret_cast<const uint8_t*>(pkSeed.data()), reinterpret_cast<uint8_t*>(hypertreeRoot.data()));

        // Initialize the Hypertree
        sphincs_ht::hypertree ht(hypertreeRoot);

        // Add the roots to the Hypertree
        for (const auto& root : roots) {
            ht.add_root(root);
        }

        // Compute the Hypertree root
        std::string hypertreeRootHash = ht.compute_root();

        // Return the computed Hypertree root
        return hypertreeRootHash;
    }

    std::string MerkleBlock::constructXMSS(const std::string& hypertreeRoot) const {
        // Set the necessary parameters for XMSS construction
        constexpr uint32_t h = 128;  // Height of the binary tree
        constexpr uint32_t d = 16;   // Number of layers in the binary tree
        constexpr size_t n = 32;     // Size of the hash output in bytes (SHA3-256)
        constexpr size_t w = 64;     // Winternitz parameter
        constexpr sphincs_hashing::variant v = sphincs_hashing::variant::SHA3_256;  // Variant of the hash function (SHA3-256)

        // Generate the secret key seed for XMSS
        std::string sk_seed = SPHINXUtils::generateSecretKeySeed();

        // Generate the public key seed for XMSS
        std::string pk_seed = SPHINXUtils::generatePublicKeySeed();

        // Create a string to store the XMSS public key
        std::string pkey(n, '\0');

        // Generate the XMSS public key using the provided parameters and seeds
        sphincs_ht::pkgen<h, d, n, w, v>(reinterpret_cast<const uint8_t*>(sk_seed.data()), reinterpret_cast<const uint8_t*>(pk_seed.data()), reinterpret_cast<uint8_t*>(pkey.data()));

        // Return the XMSS public key
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
            // Get the current pair of transactions
            std::string transaction1 = merkleTree[i];
            std::string transaction2 = (i + 1 < merkleTree.size()) ? merkleTree[i + 1] : merkleTree[i];

            // Hash the pair of transactions
            std::string hashedTransaction = hashTransactions(transaction1, transaction2);

            // Add the hashed transaction to the new Merkle tree
            newMerkleTree.push_back(hashedTransaction);
        }

        // Replace the current Merkle tree with the new one
        merkleTree = newMerkleTree;
    }


    // Return the Merkle root hash
    std::string calculatedMerkleRoot = (merkleTree.empty()) ? "" : merkleTree[0];

        return (calculatedMerkleRoot == merkleRoot);
    }

    std::string MerkleBlock::hashTransactions(const std::string& transaction1, const std::string& transaction2) const {
        // Combine and hash two transactions using the SHA3-256 hash function
        std::string concatenatedTransactions = transaction1 + transaction2;

        constexpr size_t hashOutputSize = 32;  // SHA3-256 produces a 32-byte hash output
        std::array<uint8_t, hashOutputSize> hashResult;
        SPHINXMerkleBlock::SPHINXHash::SPHINX_256(concatenatedTransactions, hashResult.data());

        // Convert the hash result to a string
        std::string finalizedHash(hashResult.begin(), hashResult.end());

        return finalizedHash;
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
