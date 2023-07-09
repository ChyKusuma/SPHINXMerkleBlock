# SPHINXMerkleBlock


## Introduction

This project is dedicated to the world community as an Open-source Post-quantum SPHINXMerkleBlock blockchain, means anyone can join and contribute based on his/ her passion and skills. SPHINX is a blockchain protocol designed to provide secure and scalable solutions in the post-quantum era.

This repository contains code for the SPHINXMerkleBlock project, which is a mining module for the SPHINX blockchain framework. The SPHINXMerkleBlock aims to provide a "Merkle trees" in the blockchain systems


## Components

The `SPHINX_MerkleBlock` namespace leverages the power of Merkle trees based on the state-of-the-art [SPHINCS+](https://sphincs.org/) principle, which emerged as the 4th winner in the "Post-Quantum" cryptography competition held by the National Institute of Standards and Technology ([NIST](https://www.nist.gov/publications/breaking-category-five-sphincs-sha-256)).

SPHINCS+ (Stateless PHotonic Isogeny-based Signature Scheme) is a groundbreaking hybrid signature scheme that combines robust hash-based, code-based, and isogeny-based cryptographic components. Its primary goal is to achieve two critical properties: "statelessness" and post-quantum security.

In the advent of quantum computers, which have the potential to render traditional cryptographic algorithms vulnerable, the elimination or reduction of reliance on state becomes imperative. Quantum computers, with their ability to exist in multiple states simultaneously, pose significant risks to storing sensitive content in state. The concept of "statelessness" in SPHINCS+ aims to mitigate these risks by eliminating the reliance on state, providing resilience against attacks by powerful quantum computers.

Unlike alternative post-quantum digital signature algorithms such as [Crystals-dilithium](https://pq-crystals.org/dilithium/), which offer high levels of security but are susceptible to side-channel attacks, our decision to employ SPHINCS+ as the foundation for our Merkle tree scheme and digital signature scheme ensures both the robustness against quantum adversaries and resistance to side-channel attacks.

With the SPHINX_MerkleBlock namespace, we empower developers to harness the advanced capabilities of SPHINCS+ and build secure, future-proof applications that can withstand the challenges posed by the dawn of the quantum era.

We know that Hash-Based digital signature scheme is not lattice-based and relly on the strengthness of the hash-function, thats why our default `SPHINX_256` hash function is based on SWIFFTX which is rely on "Lattice-based", here we try achieve "Statelessness" and "Lattice-based" at once.


NOTE; This repository only implement "Merkle trees" scheme based on SPHINCS+ principle, for actual SPHINCS+ digital signature we separated that into another files.


## Components

### `SPHINX_MerkleBlock` Namespace

This code represents the implementation of the `SPHINX_MerkleBlock` namespace, which includes the `MerkleBlock` class responsible for constructing and verifying Merkle trees. Let's break down the important components and their functions:

#### `SPHINX_MerkleBlock::MerkleBlock Class`

This class is responsible for constructing and verifying Merkle trees using various constructions such as FORS, WOTS, Hypertree, and XMSS. It contains the following functions:

- `constructMerkleTree(const std::vector<SignedTransaction>& signedTransactions)`: This function constructs a Merkle tree from a vector of signed transactions. It recursively divides the transactions into halves and combines the hashes of the left and right subtrees to compute the Merkle root.

- `verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& transactions)`: This function verifies if a given Merkle root matches the constructed Merkle root from a vector of transactions. It calculates the constructed Merkle root using the `buildMerkleRoot` function and compares it with the provided Merkle root.

- `hashTransactions(const std::string& transaction1, const std::string& transaction2)`: This function hashes two transactions using the SPHINX-256 hash function. It concatenates the transactions and computes their hash.

- `buildMerkleRoot(const std::vector<std::string>& transactions)`: This function builds the Merkle root from a vector of transactions. It applies various constructions such as FORS, WOTS, Hypertree, and XMSS to construct the Merkle root.

The `MerkleBlock` class also contains private helper classes (`ForsConstruction`, `WotsConstruction`, `HypertreeConstruction`, and `XmssConstruction`) responsible for specific parts of the Merkle tree construction process.

These components work together to provide functionality for constructing and verifying Merkle trees using the SPHINX cryptographic scheme.


### This repository is part of the  [SPHINXPoW](https://github.com/SPHINX-HUB-ORG/SPHINXPoW) [SPHINXBlock](https://github.com/SPHINX-HUB-ORG/SPHINXBLOCK) [SPHINXChain](https://github.com/SPHINX-HUB-ORG/SPHINXCHAIN) 

Please note that the code in this repository is a part of the SPHINX blockchain algorithm, which is currently in development and not fully integrated or extensively tested for functionality. The purpose of this repository is to provide a framework and algorithm for the mining scheme in the SPHINX blockchain project.

As the project progresses, further updates and enhancements will be made to ensure the code's stability and reliability. We encourage contributors to participate in improving and refining the SPHINXBlock algorithm by submitting pull requests and providing valuable insights.

We appreciate your understanding and look forward to collaborative efforts in shaping the future of the SPHINX blockchain project.

## Getting Started
To get started with the SPHINX blockchain project, follow the instructions below:

1. Clone the repository: `git clone https://github.com/ChyKusuma/SPHINXMerkleBlock.git`
2. Install the necessary dependencies (List the dependencies or provide a link to the installation guide).
3. Explore the codebase to understand the project structure and components.
4. Run the project or make modifications as needed.


## Contributing
We welcome contributions from the developer community to enhance the SPHINX blockchain project. If you are interested in contributing, please follow the guidelines below:

1. Fork the repository on GitHub.
2. Create a new branch for your feature or bug fix: `git checkout -b feature/your-feature-name` or `git checkout -b bugfix/your-bug-fix`.
3. Make your modifications and ensure the code remains clean and readable.
4. Write tests to cover the changes you've made, if applicable.
5. Commit your changes: `git commit -m "Description of your changes"`.
6. Push the branch to your forked repository: `git push origin your-branch-name`.
7. Open a pull request against the main repository, describing your changes and the problem it solves.
8. Insert your information (i.e name, email) in the authors space.

## License
Specify the license under which the project is distributed (MIT License).

## Contact
If you have any questions, suggestions, or feedback regarding the SPHINX blockchain project, feel free to reach out to us at [sphinxfounders@gmail.com](mailto:sphinxfounders@gmail.com).
