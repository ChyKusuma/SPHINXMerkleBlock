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
// The provided code defines a set of classes and functions related to a cryptographic protocol using the SPHINCS+ `merkle-trees` and `signature` scheme. This protocol is used to verify the integrity and authenticity of a chain of transactions. Let's break down the code and explain its components in detail:

// Libraries and Namespaces:
    // The code uses the "nlohmann::json" library for JSON handling.
    // It defines a namespace "SPHINXKey" and a nested namespace "SPHINXMerkleBlock" to organize the classes and functions related to the SPHINX signature scheme and Merkle tree construction.

// Type Definitions:
    // The code defines the type "SPHINXPubKey" as an alias for "std::vector<unsigned char>" in the "SPHINXKey" namespace.

// Class Definitions:
    // "SPHINXMerkleBlock::Transaction": Represents a single transaction in the Merkle tree, with fields for data, signature, and the public key used for verification.
    // "SPHINXMerkleBlock::SignedTransaction": Contains the necessary information for a signed transaction, including the transaction data, signature, data, and public key.
    // "SPHINXMerkleBlock::MerkleBlock": This is the main class representing the Merkle tree. It contains helper functions and nested construction classes for building the Merkle tree and verifying its integrity.

// Helper Functions:
    // Various helper functions like "sphinxKeyToString" and "generateHybridKeyPair" are defined to convert SPHINXPubKey to a string representation and generate a hybrid key pair.

// Merkle Tree Construction:
    // The "MerkleBlock" class contains nested construction classes for different parts of the Merkle tree: "ForsConstruction," "WotsConstruction," "HypertreeConstruction," and "XmssConstruction." These classes are used for constructing various components of the tree.

// Verification Functions:
    // "calculateBlockHeaderHash": This function calculates the hash of the block's header, including the Merkle root, for verifying the integrity of the block.
    // "verifyIntegrity": This function calls "verifyBlock" and "verifyChain" functions from "Verify.hpp" to verify the integrity of a block and the entire chain.

// Merkle Tree Construction and Verification Functions:
    // "constructMerkleTree": This function recursively constructs the Merkle tree from a vector of signed transactions.
    // "verifyMerkleRoot": This function verifies the Merkle root against a vector of transactions by checking their signatures and then building the Merkle tree and comparing its root with the provided one.

// Other Helper Functions:
    // "hashTransactions": This function hashes two transactions using the SPHINX_256 hash function.
    // "buildMerkleRoot": This function recursively constructs the Merkle root from a vector of transactions.
    // "sign" and "verify": These functions are used to sign and verify a message using the SPHINX signature scheme.

// Interactions:

    // The "MerkleBlock" class is used to construct and verify the Merkle tree for the transactions included in a block. It is called from the "Block" class to calculate and set the Merkle root of the block.
    // The "Block" class interacts with the "MerkleBlock" class to obtain the Merkle root, which is then used to sign the block with SPHINCS+ private key. The signed block is then stored, and the Merkle root and signature are added to the block's header.
    // When verifying the block's integrity, the "Block" class calls functions from the "MerkleBlock" class to verify the signature and Merkle root against the transactions.

// By adhering to these principles, the code achieves a stateless characteristic, where each invocation of the code produces consistent and predictable results without relying on or modifying any shared or persistent state.
/////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <cstdint>

#include "lib/Sphincs/include/fors.hpp"
#include "lib/Sphincs/include/wots.hpp"
#include "lib/Sphincs/include/xmss.hpp"
#include "lib/Sphincs/include/hypertree.hpp"
#include "lib/Sphincs/include/address.hpp"
#include "lib/Sphincs/include/hashing.hpp"
#include "lib/Sphincs/include/sphincs.hpp"
#include "Merkleblock_error.hpp"

#include "Hash.hpp"
#include "Block.hpp"
#include "Sign.hpp"
#include "Utils.hpp"
#include "Transaction.hpp"
#include "json.hpp"
#include "Key.hpp"
#include "Params.hpp"
#include "MerkleBlock.hpp"


using json = nlohmann::json;

// Forward declarations for functions that are defined later in "Merkleblock.cpp"
std::string generateOrRetrieveSecretKeySeed();
std::string generateOrRetrievePublicKeySeed();
bool verifySignature(const std::string& data, const std::string& signature, const SPHINXMerkleBlock::SPHINXPubKey& publicKey);

// Define the SPHINXPubKey type here (if not already defined)
namespace SPHINXKey {
    using SPHINXPubKey = std::vector<unsigned char>;
}

namespace SPHINXMerkleBlock {

    class Transaction {
    public:
        std::string data;
        std::string signature;
        SPHINXKey::SPHINXPubKey publicKey;

        // Function to convert SPHINXPubKey to string representation
        std::string sphinxKeyToString(const SPHINXKey::SPHINXPubKey& publicKey) {
            std::ostringstream oss;
            for (const auto& byte : publicKey) {
                // Convert each byte of the public key to its two-digit hexadecimal representation
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(byte);
            }
            return oss.str(); // Return the concatenated hexadecimal string
        }

        // Other member functions

        std::string toJson() const {
            json transactionJson;
            transactionJson["data"] = data;
            transactionJson["signature"] = signature;
            // Convert publicKey to string using sphinxKeyToString function
            transactionJson["publicKey"] = sphinxKeyToString(publicKey); 
            return transactionJson.dump();
        }
    };

    // Forward declarations for functions that are defined later
    bool verifySignature(const std::string& data, const std::string& signature, const SPHINXKey::SPHINXPubKey& publicKey);

    // Constants
    constexpr int SPHINCS_N = 256;
    constexpr int SPHINCS_H = 128;
    constexpr int SPHINCS_D = 64;
    constexpr int SPHINCS_A = 32;
    constexpr int SPHINCS_K = 16;
    constexpr int SPHINCS_W = 8;
    constexpr int SPHINCS_V = 4;


    // SignedTransaction structure
    struct SignedTransaction {
        Transaction transaction;
        std::string transactionData;
        std::vector<uint8_t> data;
        std::string signature;
        SPHINXKey::SPHINXPubKey publicKey;
    };

    // MerkleBlock class
    class MerkleBlock {
    public:
        // Helper functions for Merkle Tree construction
        std::string hashTransactions(const std::string& transaction1, const std::string& transaction2) const;
        std::string buildMerkleRoot(const std::vector<std::string>& transactions) const;
        bool sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk_seed, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, std::vector<uint8_t>& sig);
        bool verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, const std::vector<uint8_t>& pkey) const;

        // Construct the Merkle tree from a vector of signed transactions
        std::string constructMerkleTree(const std::vector<SignedTransaction>& signedTransactions);

        // Verify the Merkle root against a vector of transactions
        bool verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& transactions);

        // Add the function to generate the hybrid key pair
        static std::pair<std::string, SPHINXKey::SPHINXPubKey> generateHybridKeyPair();

    private:
        // Nested construction classes
        class ForsConstruction {
        public:
            // Construct a FORS tree from a vector of transactions
            std::vector<std::string> constructForsTree(const std::vector<std::string>& transactions);
        };

        class WotsConstruction {
        public:
            // Construct a WOTS tree from a vector of roots
            std::vector<std::string> constructWotsTree(const std::vector<std::string>& roots, size_t n) const;
        };

        class HypertreeConstruction {
        public:
            // Construct a Hypertree from a vector of roots
            std::string constructHypertree(const std::vector<std::string>& roots) const;
        };

        class XmssConstruction {
        public:
            // Generate an XMSS public key using the provided secret key seed and public key seed
            std::string pkgen(const std::string& sk_seed, const std::string& pk_seed, std::string& pkey) const;

            // Construct an XMSS public key using the Hypertree root
            std::string constructXMSS(const std::string& hypertreeRoot) const;
        };

        // Private members for construction classes
        ForsConstruction forsConstruction;
        WotsConstruction wotsConstruction;
        HypertreeConstruction hypertreeConstruction;
        XmssConstruction xmssConstruction;
    };

    // Function to calculate the hash of the block's header, including the Merkle root
    std::string calculateBlockHeaderHash(const std::string& prevBlockHash, const std::string& merkleRoot, const std::string& timestamp, const std::string& nonce) {
        std::string headerData = prevBlockHash + merkleRoot + timestamp + nonce;
        // Assuming SPHINXHash::SPHINX_256 is available to calculate the SHA-256 hash
        return SPHINXHash::SPHINX_256(headerData);
    }

    // Function to call verifyBlock and verifyChain functions from Verify.hpp and print the results
    void verifyIntegrity(const SPHINXMerkleBlock::MerkleBlock& block, const SPHINXMerkleBlock::SPHINXChain& chain) {
        // Call verifyBlock to verify the integrity of the block
        bool blockVerified = SPHINXMerkleBlock::verifyBlock(block);
        if (blockVerified) {
            std::cout << "Block integrity is valid.\n";
        } else {
            std::cout << "Block integrity is NOT valid.\n";
        }

        // Call verifyChain to verify the integrity of the entire chain
        bool chainVerified = SPHINXMerkleBlock::verifyChain(chain);
        if (chainVerified) {
            std::cout << "Chain integrity is valid.\n";
        } else {
            std::cout << "Chain integrity is NOT valid.\n";
        }
    }

    // Function to convert SPHINXPubKey to string representation
    std::string sphinxKeyToString(const SPHINXKey::SPHINXPubKey& publicKey) {
        // Use the correct function from "Key.cpp" to convert public key to string
        return SPHINXKey::sphinxKeyToString(publicKey);
    }

    // Function to generate the hybrid key pair using the necessary functions and algorithms
    std::pair<std::string, SPHINXKey::SPHINXPubKey> generateHybridKeyPair() {
        // Generate the hybrid key pair using the functions from "Key.cpp"
        SPHINXHybridKey::HybridKeypair hybridKeyPair = SPHINXKey::generate_hybrid_keypair();

        // Convert the private key to string
        std::string privateKeyString = sphinxKeyToString(hybridKeyPair.merged_key.sphinxPrivKey);

        // Convert the public key to string
        std::string publicKeyString = sphinxKeyToString(hybridKeyPair.merged_key.sphinxPubKey);

        // Return the hybrid key pair as a std::pair
        return std::make_pair(privateKeyString, hybridKeyPair.merged_key.sphinxPubKey);
    }

    // Function to construct the Merkle tree from a vector of signed transactions
    std::string MerkleBlock::constructMerkleTree(const std::vector<SignedTransaction>& signedTransactions) {
        // If there are no signed transactions, return an empty string as the Merkle root
        if (signedTransactions.empty()) {
            return "";
        }

        // If there is only one signed transaction, return its data as the Merkle root
        if (signedTransactions.size() == 1) {
            return signedTransactions[0].transaction.data;
        }

        // Divide the list of signed transactions into two halves
        size_t mid = signedTransactions.size() / 2;
        std::vector<SignedTransaction> leftTransactions(signedTransactions.begin(), signedTransactions.begin() + mid);
        std::vector<SignedTransaction> rightTransactions(signedTransactions.begin() + mid, signedTransactions.end());

        // Recursively construct the Merkle root of the left subtree
        std::string leftRoot = constructMerkleTree(leftTransactions);
        // Recursively construct the Merkle root of the right subtree
        std::string rightRoot = constructMerkleTree(rightTransactions);

        // Combine the Merkle roots of the left and right subtrees using the hashTransactions function
        return hashTransactions(leftRoot, rightRoot);
    }

    // Function to verify the Merkle root against a vector of transactions
    bool MerkleBlock::verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& transactions) {
        // Create a list to hold valid transaction data
        std::vector<std::string> transactionList;
        for (const auto& transaction : transactions) {
            // Verify the signature of each transaction using the verifySignature function
            if (verifySignature(transaction.transaction.data, transaction.transaction.signature, transaction.transaction.publicKey)) {
                // If the signature is valid, add the transaction data to the list
                transactionList.push_back(transaction.transaction.data);
            } else {
                // If the signature is invalid, print an error message and return false
                std::cerr << "ERROR: Invalid signature for transaction: " << transaction.transaction.data << std::endl;
                return false;
            }
        }

        // Create a list to hold the transaction data as objects
        std::vector<std::string> transactionObjects;
        for (const auto& transactionData : transactionList) {
            transactionObjects.push_back(transactionData);
        }

        // Construct the Merkle root from the list of valid transaction data using the buildMerkleRoot function
        std::string constructedRoot = buildMerkleRoot(transactionObjects);

        // Compare the constructed Merkle root with the provided Merkle root
        if (constructedRoot == merkleRoot) {
            // If they match, the Merkle root is valid, and we return true
            return true;
        } else {
            // If they do not match, print an error message and return false
            std::cerr << "ERROR: Invalid Merkle root" << std::endl;
            return false;
        }
    }

    // Function to calculate the hash of two transactions using the SPHINX_256 hash function
    std::string MerkleBlock::hashTransactions(const std::string& transaction1, const std::string& transaction2) const {
        // Assuming the SPHINX_256 hash function is available in the library
        std::string hash = SPHINXHash::SPHINX_256(transaction1 + transaction2);
        return hash;
    }

    // Function to construct the Merkle root from a vector of transactions
    std::string MerkleBlock::buildMerkleRoot(const std::vector<std::string>& transactions) const {
        // If there are no transactions, return an empty string as the Merkle root
        if (transactions.empty()) {
            return "";
        }

        // If there is only one transaction, return its hash as the Merkle root
        if (transactions.size() == 1) {
            // Assuming the SPHINX_256 hash function is available in the library
            return SPHINXHash::SPHINX_256(transactions[0]);
        }

        // Divide the list of transactions into two halves
        size_t mid = transactions.size() / 2;
        std::vector<std::string> leftTransactions(transactions.begin(), transactions.begin() + mid);
        std::vector<std::string> rightTransactions(transactions.begin() + mid, transactions.end());

        // Recursively construct the Merkle root of the left subtree
        std::string leftRoot = buildMerkleRoot(leftTransactions);
        // Recursively construct the Merkle root of the right subtree
        std::string rightRoot = buildMerkleRoot(rightTransactions);

        // Combine the Merkle roots of the left and right subtrees using the hashTransactions function
        // Assuming the SPHINX_256 hash function is available in the library
        return SPHINXHash::SPHINX_256(leftRoot + rightRoot);
    }

    // Function to sign a message using the SPHINCS signature scheme
    bool MerkleBlock::sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk_seed, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, std::vector<uint8_t>& sig) {
        std::vector<uint8_t> signature;
        // Call the SPHINCS signing function with appropriate parameters
        sphincs::sign<SPHINCS_N, SPHINCS_H, SPHINCS_D, SPHINCS_A, SPHINCS_K, SPHINCS_W, SPHINCS_V>(msg.data(), msg.size(), sk_seed.data(), idx_tree, idx_leaf, pk_seed.data(), signature.data());

        // Assign the generated signature to the provided vector
        sig.assign(signature.begin(), signature.end());

        // Verify the generated signature using the SPHINCS verification function
        return sphincs::verify<SPHINCS_N, SPHINCS_H, SPHINCS_D, SPHINCS_A, SPHINCS_K, SPHINCS_W, SPHINCS_V>(msg.data(), msg.size(), sig.data(), pk_seed.data());
    }

    // Function to construct the FORS tree from a vector of transactions
    std::vector<std::string> MerkleBlock::ForsConstruction::constructForsTree(const std::vector<std::string>& transactions) {
        // Implementation of constructing FORS tree
        constexpr size_t n = 32;
        constexpr uint32_t a = 32;
        constexpr uint32_t k = 8;
        constexpr sphincs_hashing::variant = sphincs_hashing::variant::robust;

        uint8_t pk[n];
        // Generate the public key using the provided parameters and the SPHINCS FORS function
        sphincs_fors::pkgen<n, a, k, variant::robust>(nullptr, nullptr, sphincs_adrs::fors_tree_t(), pk);

        // Convert the public key to a string representation
        std::string pkString(pk, pk + n);

        // Return the public key as a single element vector
        return {pkString};
    }

    // Function to construct the WOTS tree from a vector of roots
    std::vector<std::string> MerkleBlock::WotsConstruction::constructWotsTree(const std::vector<std::string>& roots, size_t n) const {
        // Implementation of constructing WOTS tree
        std::vector<std::string> wotsTree;
        for (const auto& root : roots) {
            std::array<uint8_t, n> message;

            // Sign each root using the SPHINCS WOTS function and store the signature as a string
            sphincs_wots::sign<n, SPHINCS_W, sphincs_hashing::variant::robust>(reinterpret_cast<const uint8_t*>(root.data()), nullptr, nullptr, sphincs_adrs::fors_tree_t(), message.data());

            std::string wotsSignature(reinterpret_cast<const char*>(message.data()), n);
            wotsTree.push_back(wotsSignature);
        }

        // Return the vector of WOTS signatures
        return wotsTree;
    }

    // Function to construct the Hypertree from a vector of roots
    std::string MerkleBlock::HypertreeConstruction::constructHypertree(const std::vector<std::string>& roots) const {
        // Implementation of constructing Hypertree
        constexpr uint32_t h = 128;
        constexpr uint32_t d = 16;
        constexpr size_t n = 32;
        constexpr size_t w = 64;
        constexpr sphincs_hashing::variant = sphincs_hashing::variant::robust;

        // Generate or retrieve the secret key seed
        std::string skSeed = generateOrRetrieveSecretKeySeed();
        // Generate or retrieve the public key seed
        std::string pkSeed = generateOrRetrievePublicKeySeed();
        // Initialize the root of the Hypertree as a null-filled string
        std::string hypertreeRoot(n, '\0');

        // Generate the public key of the Hypertree using the provided seeds and parameters
        sphincs_ht::pkgen<h, d, n, w, variant::robust>(reinterpret_cast<const uint8_t*>(skSeed.data()), reinterpret_cast<const uint8_t*>(pkSeed.data()), reinterpret_cast<uint8_t*>(hypertreeRoot.data()));

        // Create a Hypertree object with the generated public key
        sphincs_ht::hypertree ht(hypertreeRoot);

        // Add each root to the Hypertree
        for (const auto& root : roots) {
            ht.add_root(root);
        }

        // Compute the root hash of the Hypertree
        std::string hypertreeRootHash = ht.compute_root();

        return hypertreeRootHash;
    }

    // Function to generate an XMSS public key using the provided secret key seed and public key seed
    std::string MerkleBlock::XmssConstruction::pkgen(const std::string& sk_seed, const std::string& pk_seed, std::string& pkey) const {
        // Implementation of XMSS public key generation
        constexpr uint32_t h = 128;
        constexpr uint32_t d = 16;
        constexpr size_t n = 32;
        constexpr size_t w = 64;
        constexpr sphincs_hashing::variant = sphincs_hashing::variant::robust;

        // Generate the public key of the XMSS using the provided secret key seed and public key seed
        sphincs_ht::pkgen<h, d, n, w, variant::robust>(reinterpret_cast<const uint8_t*>(sk_seed.data()), reinterpret_cast<const uint8_t*>(pk_seed.data()), reinterpret_cast<uint8_t*>(pkey.data()));

        return pkey;
    }

    // Function to construct an XMSS public key using the Hypertree root
    std::string MerkleBlock::XmssConstruction::constructXMSS(const std::string& hypertreeRoot) const {
        // Implementation of constructing XMSS public key
        constexpr uint32_t h = 128;
        constexpr uint32_t d = 16;
        constexpr size_t n = 32;
        constexpr size_t w = 64;
        constexpr sphincs_hashing::variant = sphincs_hashing::variant::robust;

        // Generate the secret key seed
        std::string sk_seed = generateSecretKeySeed();
        // Generate the public key seed
        std::string pk_seed = generatePublicKeySeed();
        // Initialize the XMSS public key as a null-filled string
        std::string pkey(n, '\0');

        // Generate the XMSS public key using the provided Hypertree root and seeds
        sphincs_ht::pkgen<h, d, n, w, variant::robust>(reinterpret_cast<const uint8_t*>(sk_seed.data()), reinterpret_cast<const uint8_t*>(pk_seed.data()), reinterpret_cast<uint8_t*>(pkey.data()));

        return pkey;
    }

    // Function to verify the signature of a transaction data using the provided public key
    bool verifySignature(const std::string& data, const std::string& signature, const SPHINXKey::SPHINXPubKey& publicKey) {
        // Assuming SPHINXUtils::verifySignature function is available in the library
        // Verify the signature of the given data using the provided public key
        bool signatureValid = SPHINXUtils::verifySignature(data, signature, publicKey);
        return signatureValid;
    }
} // namespace SPHINXMerkleBlock


int main() {
    using namespace SPHINXMerkleBlock;

    // Sample list of signed transactions
    std::vector<SignedTransaction> signedTransactions;

    // Add some transactions to the list (for demonstration purposes)
    // You should replace these transactions with actual signed transactions
    SignedTransaction transaction1;
    transaction1.transaction.data = "Transaction Data 1";
    transaction1.transaction.signature = "Signature 1";
    // Assuming SPHINXKey::generateHybridKeyPair() generates the hybrid key pair
    transaction1.transaction.publicKey = generateHybridKeyPair().second;
    signedTransactions.push_back(transaction1);

    SignedTransaction transaction2;
    transaction2.transaction.data = "Transaction Data 2";
    transaction2.transaction.signature = "Signature 2";
    // Assuming SPHINXKey::generateHybridKeyPair() generates the hybrid key pair
    transaction2.transaction.publicKey = generateHybridKeyPair().second;
    signedTransactions.push_back(transaction2);

    SignedTransaction transaction3;
    transaction3.transaction.data = "Transaction Data 3";
    transaction3.transaction.signature = "Signature 3";
    // Assuming SPHINXKey::generateHybridKeyPair() generates the hybrid key pair
    transaction3.transaction.publicKey = generateHybridKeyPair().second;
    signedTransactions.push_back(transaction3);

    // Create a MerkleBlock instance
    MerkleBlock merkleBlock;

    // Construct the Merkle tree from the list of signed transactions
    std::string merkleRoot = merkleBlock.constructMerkleTree(signedTransactions);

    // Print the Merkle root
    std::cout << "Merkle Root: " << merkleRoot << std::endl;

    // Verify the Merkle root against the list of transactions
    bool isMerkleRootValid = merkleBlock.verifyMerkleRoot(merkleRoot, signedTransactions);

    // Print the verification result
    if (isMerkleRootValid) {
        std::cout << "Merkle Root is valid." << std::endl;
    } else {
        std::cout << "Merkle Root is NOT valid." << std::endl;
    }

    return 0;
}