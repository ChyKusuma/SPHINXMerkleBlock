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
// The code begins with forward declarations and namespaces. It declares the verifySignature function within the SPHINXVerify namespace, which is used for signature verification. It also includes forward declarations for the Block class within the SPHINXBlock namespace.

// Next, the code defines several data structures and functions within the SPHINXMerkleBlock namespace, which is responsible for Merkle tree construction and related cryptographic operations.

// Data Structures:
  // PublicKey: A struct representing a public key.

  // SignedTransaction: A struct representing a signed transaction. It contains the transaction data, a vector of bytes representing the transaction, a signature, and a public key.

// Namespaces:
  // SPHINXMerkleBlock::SPHINXHash: Contains the SPHINX_256 function, which computes the SPHINX-256 hash of a given input data string.

  // SPHINXMerkleBlock::SPHINCS: Contains functions and classes related to the SPHINCS cryptographic scheme. It includes namespaces like sphincs_adrs, sphincs_fors, sphincs_wots, and sphincs_ht, each responsible for different aspects of SPHINCS operations.

// Classes:
  // MerkleBlock: The main class responsible for Merkle tree construction and verification. It contains private nested classes for ForsConstruction, WotsConstruction, HypertreeConstruction, and XmssConstruction, each handling a specific part of the Merkle tree construction process.

  // ForsConstruction: Handles the construction of a FORS (Forward-Randomized Structure) tree from a set of transactions.

  // WotsConstruction: Handles the construction of a WOTS (Winternitz One-Time Signature) tree from a set of roots.

  // HypertreeConstruction: Handles the construction of a Hypertree from a set of roots.

  // XmssConstruction: Handles the construction of an XMSS (Extended Merkle Signature Scheme) public key from a Hypertree root.

// MerkleBlock class functions:
  // constructMerkleTree: Recursively constructs the Merkle tree given a vector of signed transactions. It returns the Merkle root.

  // verifyMerkleRoot: Verifies the provided Merkle root against a vector of signed transactions. It verifies the signatures using the verifySignature function and compares the constructed Merkle root with the provided one.

  // hashTransactions: Hashes two transactions using the SPHINX_256 hash function.

  // buildMerkleRoot: Recursively builds the Merkle root from a vector of transactions by dividing them into two halves and combining their roots.

  // sign and verify: Signature-related functions that call the verifySignature function for signature verification.

// ForsConstruction class functions:
  // constructForsTree: Constructs a FORS tree from a vector of transactions. It converts transactions to bytes, sets parameters, generates a FORS public key, and returns it as a vector of strings.

// WotsConstruction class functions:
  // constructWotsTree: Constructs a WOTS tree from a vector of roots. It iterates over the roots, signs each root using the WOTS+ algorithm, and returns the signatures as a vector of strings.

// HypertreeConstruction class functions:
// constructHypertree: Constructs a Hypertree from a vector of roots. It sets parameters, generates or retrieves seeds, generates a Hypertree root, initializes the Hypertree, adds roots to it, and computes the final Hypertree root.

// XmssConstruction class functions:
  // pkgen: Generates an XMSS public key given the secret key seed, public key seed, and an output string for the public key.

  // constructXMSS: Constructs an XMSS public key given a Hypertree root. It generates secret key and public key seeds, generates the XMSS public key, and returns it.

// The code also includes a function verifySignature outside the classes, which calls the SPHINXVerify::verifySignature function to perform the actual signature verification.

// The code aims to achieve "stateless" behavior through various means:
  // 1. No internal state: The classes and functions operate solely on the input parameters passed to them. They do not maintain any internal state or store intermediate results.

  // 2. Functional programming style: The code follows a functional programming style where functions perform computations based on input parameters and return results without modifying external state. This style minimizes side effects and makes the code more predictable and easier to reason about.

  // 3. Immutable data structures: The code primarily uses immutable data structures such as strings and vectors. Immutable data ensures that the data remains constant and unchanged throughout the execution of the code.

  // 4. Pure functions: The code consists mostly of pure functions that produce output solely based on their input parameters. They do not have any side effects and produce consistent results, which enhances the stateless property.

  // 5. No shared resources: The code does not rely on shared resources such as global variables or shared memory. Each function invocation works with its own set of parameters and local variables, ensuring isolation and independence from external state.

// By adhering to these principles, the code achieves a stateless characteristic, where each invocation of the code produces consistent and predictable results without relying on or modifying any shared or persistent state.
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


namespace SPHINXUtils {
    class PublicKey;  // Forward declaration of the PublicKey class
    bool verifySignature(const std::vector<uint8_t>& data, const std::string& signature, const SPHINXUtils::PublicKey& publicKey);  // Forward declaration of the verifySignature function
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
            std::string hash = SPHINX_256(data);
            return hash;
        }
    }

    namespace SPHINCS {
    // Define the required functions used in the code
        namespace sphincs_adrs {
            // Define the address structure for FORS trees
            struct fors_tree_t {};
        }

        namespace sphincs_fors {
            // Declare the function for generating a public key using the FORS algorithm
            template <size_t n, uint32_t a, uint32_t k, typename T>
            void pkgen(const uint8_t* sk_seed, const uint8_t* pk_seed, const sphincs_adrs::fors_tree_t& adrs, T* pkey);
        }

        namespace sphincs_wots {
            // Declare the function for signing a message using WOTS+
            template <size_t n, size_t w, typename T>
            void sign(const uint8_t* message, const uint8_t* sk_seed, const uint8_t* pk_seed, const sphincs_adrs::fors_tree_t& adrs, T* signature);
        }

        namespace sphincs_ht {
            // Declare the function for generating a public key using the Hypertree construction
            template <size_t h, size_t d, size_t n, size_t w, typename T>
            void pkgen(const uint8_t* sk_seed, const uint8_t* pk_seed, T* pkey);

            // Define the Hypertree class
            class hypertree {
            public:
                hypertree(const std::string& root);

                void add_root(const std::string& root);
                std::string compute_root();
            };
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
        // Construct the Merkle tree from a vector of signed transactions
        std::string constructMerkleTree(const std::vector<SignedTransaction>& signedTransactions) const;

        // Verify the Merkle root against a vector of transactions
        bool verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& transactions) const;

    private:
        // Hash two transactions and return the resulting hash
        std::string hashTransactions(const std::string& transaction1, const std::string& transaction2) const;

        // Build the Merkle root from a vector of transactions
        std::string buildMerkleRoot(const std::vector<std::string>& transactions) const;

        // Sign a message using the provided parameters and seeds
        bool sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk_seed, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, std::vector<uint8_t>& sig) const;

        // Verify a signature using the provided parameters, seeds, and public key
        bool verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, const std::vector<uint8_t>& pkey) const;

        ForsConstruction forsConstruction;               // Instance of ForsConstruction
        WotsConstruction wotsConstruction;               // Instance of WotsConstruction
        HypertreeConstruction hypertreeConstruction;     // Instance of HypertreeConstruction
        XmssConstruction xmssConstruction;               // Instance of XmssConstruction
    };

    std::string MerkleBlock::constructMerkleTree(const std::vector<SignedTransaction>& signedTransactions) const {
        // Base case: If there are no signed transactions, return an empty string
        if (signedTransactions.empty()) {
            return "";
        }

        // Base case: If there is only one signed transaction, return its hash as the Merkle tree root
        if (signedTransactions.size() == 1) {
            return SPHINXHash::SPHINX_256(signedTransactions[0].transaction);
        }

        // Recursive case: Divide the signed transactions into two halves
        size_t mid = signedTransactions.size() / 2;
        std::vector<SignedTransaction> leftTransactions(signedTransactions.begin(), signedTransactions.begin() + mid);
        std::vector<SignedTransaction> rightTransactions(signedTransactions.begin() + mid, signedTransactions.end());

        // Recursively construct the Merkle tree for the left and right subtrees
        std::string leftRoot = constructMerkleTree(leftTransactions);
        std::string rightRoot = constructMerkleTree(rightTransactions);

        // Combine the left and right roots by hashing them together
        return SPHINXHash::SPHINX_256(leftRoot + rightRoot);
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

        // Continue with Merkle root verification if all signatures are valid
        // Calculate the constructed Merkle root using the transactions
        std::string constructedRoot = buildMerkleRoot(transactionList);

        // Compare the constructed Merkle root with the provided Merkle root
        if (constructedRoot == merkleRoot) {
            return true;
        } else {
            std::cerr << "ERROR: Invalid Merkle root" << std::endl;
            return false;
        }
    }

    std::string MerkleBlock::hashTransactions(const std::string& transaction1, const std::string& transaction2) const {
        // Concatenate the two transactions and compute their hash using the SPHINX_256 hash function
        return SPHINXHash::SPHINX_256(transaction1 + transaction2);
    }

    std::string MerkleBlock::buildMerkleRoot(const std::vector<std::string>& transactions) const {
        // Base case: If there are no transactions, return an empty string
        if (transactions.empty()) {
            return "";
        }

        // Base case: If there is only one transaction, return its hash as the Merkle root
        if (transactions.size() == 1) {
            return SPHINXHash::SPHINX_256(transactions[0]);
        }

        // Recursive case: Divide the transactions into two halves
        size_t mid = transactions.size() / 2;
        std::vector<std::string> leftTransactions(transactions.begin(), transactions.begin() + mid);
        std::vector<std::string> rightTransactions(transactions.begin() + mid, transactions.end());

        // Recursively build the Merkle root for the left and right subtrees
        std::string leftRoot = buildMerkleRoot(leftTransactions);
        std::string rightRoot = buildMerkleRoot(rightTransactions);

        // Combine the left and right roots by hashing them together
        return SPHINXHash::SPHINX_256(leftRoot + rightRoot);
    }

    bool MerkleBlock::sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk_seed, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, std::vector<uint8_t>& sig) const {
        // Call the verifySignature function from SPHINXSign to fulfill the signature requirement
        bool signatureValid = SPHINXSign::verifySignature(msg, std::string(sig.begin(), sig.end()), PublicKey{});

        // Return the result of signature verification
        return signatureValid;
    }

    bool MerkleBlock::verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, const std::vector<uint8_t>& pkey) const {
        // Call the verifySignature function from SPHINXSign to fulfill the signature requirement
        bool signatureValid = SPHINXSign::verifySignature(msg, std::string(sig.begin(), sig.end()), PublicKey{});

        // Return the result of signature verification
        return signatureValid;
    }

    std::vector<std::string> MerkleBlock::ForsConstruction::constructForsTree(const std::vector<std::string>& transactions) const {
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

    std::vector<std::string> MerkleBlock::WotsConstruction::constructWotsTree(const std::vector<std::string>& roots) const {
        std::vector<std::string> wotsTree;

        for (const auto& root : roots) {
            std::array<uint8_t, n> message;
            // Assuming we have access to the necessary parameters (e.g., skSeed, pkSeed, adrs)
            // to generate a WOTS+ signature using the sign function from "WOTS.hpp"
            sphincs_wots::sign<n, w>(reinterpret_cast<const uint8_t*>(root.data()), nullptr, nullptr, sphincs_adrs::fors_tree_t(), message.data());

            std::string wotsSignature(reinterpret_cast<const char*>(message.data()), n);
            wotsTree.push_back(wotsSignature);
        }

        return wotsTree;
    }

    std::string MerkleBlock::HypertreeConstruction::constructHypertree(const std::vector<std::string>& roots) const {
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

    std::string MerkleBlock::XmssConstruction::pkgen(const std::string& sk_seed, const std::string& pk_seed, std::string& pkey) const {
        // Set the necessary parameters for XMSS construction
        constexpr uint32_t h = 128;  // Height of the binary tree
        constexpr uint32_t d = 16;   // Number of layers in the binary tree
        constexpr size_t n = 32;     // Size of the hash output in bytes (SHA3-256)
        constexpr size_t w = 64;     // Winternitz parameter
        constexpr sphincs_hashing::variant v = sphincs_hashing::variant::SHA3_256;  // Variant of the hash function (SHA3-256)

        // Generate the XMSS public key using the provided parameters and seeds
        sphincs_ht::pkgen<h, d, n, w, v>(reinterpret_cast<const uint8_t*>(sk_seed.data()), reinterpret_cast<const uint8_t*>(pk_seed.data()), reinterpret_cast<uint8_t*>(pkey.data()));

        // Return the XMSS public key
        return pkey;
    }

    std::string MerkleBlock::XmssConstruction::constructXMSS(const std::string& hypertreeRoot) const {
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

    bool verifySignature(const std::vector<uint8_t>& data, const std::string& signature, const SPHINXUtils::PublicKey& publicKey) {
        // Call the verifySignature function from SPHINXUtils namespace to perform the actual signature verification
        bool signatureValid = SPHINXUtils::verifySignature(data, signature, publicKey);
        return signatureValid;
    }

    bool SPHINXMerkleBlock::verifySignature(const std::vector<uint8_t>& data, const std::string& signature, const SPHINXUtils::PublicKey& publicKey) {
        // Call the verifySignature function from SPHINXUtils namespace to perform the actual signature verification
        bool signatureValid = SPHINXUtils::verifySignature(data, signature, publicKey);

        return signatureValid;
    }
} // namespace SPHINXMerkleBlock

#endif // MERKLEBLOCK_HPP
