# SPHINXMerkleBlock


## Introduction

This project is dedicated to the world community as an Open-source Post-quantum blockchain layer 1 project, means anyone can join and contribute based on his/ her passion and skills. SPHINX is a blockchain protocol designed to provide secure and scalable solutions in the post-quantum era.

This repository contains code for the SPHINXMerkleBlock project, which is a `Merkle trees` module for the SPHINX blockchain framework.


## Components

#### This repository is part of [SPHINXSign](https://github.com/SPHINX-HUB-ORG/SPHINXSign)
The `SPHINXSign` namespace leverages the power of Merkle trees based on the state-of-the-art [SPHINCS+](https://sphincs.org/) principle, which emerged as the 4th winner in the "Post-Quantum" cryptography competition held by the National Institute of Standards and Technology ([NIST](https://www.nist.gov/publications/breaking-category-five-sphincs-sha-256)).

SPHINCS+ (Stateless PHotonic Isogeny-based Signature Scheme) is a groundbreaking hybrid signature scheme that combines robust hash-based, code-based, and isogeny-based cryptographic components. Its primary goal is to achieve two critical properties: "statelessness" and post-quantum security.

In the advent of quantum computers, which have the potential to render traditional cryptographic algorithms vulnerable, the elimination or reduction of reliance on state becomes imperative. Quantum computers, with their ability to exist in multiple states simultaneously, pose significant risks to storing sensitive content in state. The concept of "statelessness" in SPHINCS+ aims to mitigate these risks by eliminating the reliance on state, providing resilience against attacks by powerful quantum computers.

Unlike alternative post-quantum digital signature algorithms such as [Crystals-dilithium](https://pq-crystals.org/dilithium/) which offer high levels of security but are susceptible to "side-channel attacks", side channel atttack means attack on devices, the bad actors can attack on devices to found the "Sign" then it can to used to sign any message that their want, our decision to employ SPHINCS+ as the foundation for our Merkle tree scheme and digital signature scheme ensures both the robustness against quantum adversaries and resistance to side-channel attacks.

With the `SPHINXSign` namespace, we empower developers to harness the advanced capabilities of SPHINCS+ and build secure, future-proof applications that can withstand the challenges posed by the dawn of the quantum era.

We know that Hash-Based digital signature scheme is not lattice-based and relly on the strengthness of the hash-function, thats why our default [SPHINXHash](https://github.com/ChyKusuma/SPHINXHash) hash function is based on SWIFFTX which is rely on "Lattice-based", here our purposed is try to achieve both `Statelessness` and `Lattice-based` together at once.

Digital signature scheme like [Gottesman-chuang](https://www.researchgate.net/publication/2186040_Quantum_Digital_Signatures) its trully guarantee by Quantum-Laws, we aware about that, but it's still too expensive technology, its needed new infrastructure, new hardware, a lot of money will only spent into infrastructure, so for today its not solution for us and not applicable. One day, when the world already build the quantum infrastructure i.e Quantum Key Distribution we believed our construction will more safe.

## Function

### JSON and SPHINXKey Namespace

- The code starts with the use of JSON library with the alias json from the nlohmann namespace.
- Next, a namespace called SPHINXKey is declared, which contains a type SPHINXPubKey representing a vector of unsigned characters. It seems to be used for public keys.

### Forward Declarations

- Three functions are forward-declared, which means their actual implementation is provided later in the code.
    - These functions are:
    - `generateOrRetrieveSecretKeySeed`: It's expected to generate or retrieve a secret key seed.
    - `generateOrRetrievePublicKeySeed`: It's expected to generate or retrieve a public key seed.
    - `verifySignature`: It's expected to verify a signature using a public key.

### SPHINXMerkleBlock Namespace

- A new namespace named `SPHINXMerkleBlock` is defined, encapsulating all the classes and functions related to constructed the Merkle block.

 ### Transaction class 
 
- The Transaction class represents a transaction and contains `data, signature`, and `publicKey` as its member variables.
It provides a member function `toJson()` to convert the transaction data into a `JSON-formatted` string.

### Constants

- Several constants are declared, such as `SPHINCS_N, SPHINCS_H, SPHINCS_D, etc`., which might be used to call function from SPHINCS+ library.

### SignedTransaction Structure

- The `SignedTransactio`n structure represents a signed transaction and includes `transaction, transactionData, data, signature`, and `publicKey` as its members.

### MerkleBlock class 

- The MerkleBlock class represents a `Merkle block` and includes several helper classes for `Merkle tree` construction: `ForsConstruction, WotsConstruction, HypertreeConstruction`, and `XmssConstruction`.
  - First the hash function used default hash function in library based on `SHAKE256 robust scheme`
  - Then it hashing again using `SPHINXHash` to ensure long term usage.

- It also contains functions for constructing the Merkle tree `(constructMerkleTree)` and verifying the Merkle root `(verifyMerkleRoot)`.

### Calculate block header

- This function takes the `previous block hash, Merkle root, timestamp`, and `nonce` as inputs and returns the hash of the block's header data.

### verifyIntegrity Function

This function calls `verifyBlock` and `verifyChain` functions from `Verify.hpp` and prints the results of block and chain integrity verification.

### sphinxKeyToString Function

- This function converts the SPHINX public key to a string representation.

### generateHybridKeyPair Function

- This function generates a hybrid key pair using functions from `Key.cpp` It returns the private key as a string and the public key as a `SPHINXKey::SPHINXPubKey`.

### MerkleTree Construction

- The `constructMerkleTree` function recursively constructs the Merkle tree from a vector of signed transactions.
verifyMerkleRoot Function

### verifyMerkleRoot Function

- The verifyMerkleRoot function verifies the Merkle root against a vector of transactions, ensuring the validity of transactions using their signatures.

### hashTransactions Function

- This function calculates the hash of two transactions using the `SPHINX_256` hash function.

### buildMerkleRoot Function

- This function constructs the Merkle root from a vector of transactions using recursion.

### Signing and Key Generation Functions

- The sign function is used for signing a message using the SPHINCS signature scheme.
- 
- The nested classes `ForsConstruction, WotsConstruction, HypertreeConstruction`, and `XmssConstruction` handle various steps in constructing the `Merkle tree`, involving different cryptographic functions.

### Verification Function
- The verifySignature function is used to verify the signature of a transaction using the provided public key.

These components work together to provide functionality for constructing and verifying Merkle trees using the SPHINX cryptographic scheme.


### Note

Every code in the repository is a part of the SPHINX blockchain algorithm, which is currently in development and not fully integrated or extensively tested for functionality. The purpose of this repository is to provide a framework and algorithm for the digital signature scheme in the SPHINX blockchain project.

As the project progresses, further updates and enhancements will be made to ensure the code's stability and reliability. We encourage contributors to participate in improving and refining the SPHINXBlock algorithm by submitting pull requests and providing valuable insights.

We appreciate your understanding and look forward to collaborative efforts in shaping the future of the SPHINX blockchain projec, to accelerating the construction you can find the SPHINCS+ specification here [SPHINCS+](https://github.com/SPHINX-HUB-ORG/SPHINXSign/blob/main/sphincs%2B-round3-specification.pdf).


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
