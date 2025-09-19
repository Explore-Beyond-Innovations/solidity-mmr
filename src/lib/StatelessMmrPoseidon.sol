// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "@poseidon2/src/Poseidon2Lib.sol";
import "@poseidon2/src/Field.sol";
import "./StatelessMmrHelpers.sol";

///    _____       _ _     _ _ _           __  __ __  __ _____
///   / ____|     | (_)   | (_) |         |  \/  |  \/  |  __ \
///  | (___   ___ | |_  __| |_| |_ _   _  | \  / | \  / | |__) |
///   \___ \ / _ \| | |/ _` | | __| | | | | |\/| | |\/| |  _  /
///   ____) | (_) | | | (_| | | |_| |_| | | |  | | |  | | | \ \
///  |_____/ \___/|_|_|\__,_|_|\__|\__, | |_|  |_|_|  |_|_|  \_\
///                                 __/ |
///                                |___/

///
/// @title StatelessMmr -- A Solidity implementation of Merkle Mountain Range
/// @author Herodotus Ltd
/// @notice Library for appending bytes32 values (i.e., acting as an accumulator)
///         and verifying Merkle inclusion proofs
///
library StatelessMmr {
    error InvalidProof();
    error IndexOutOfBounds();
    error InvalidRoot();
    error InvalidPeaksArrayLength();

    ///
    /// @notice Append a new element to the MMR
    /// @param elem Element to append
    /// @param peaks The latest peaks
    /// @param lastElementsCount The latest elements count
    /// @param lastRoot  The latest root
    /// @return The updated elements count and the new root hash of the tree
    ///
    function append(bytes32 elem, bytes32[] memory peaks, uint256 lastElementsCount, bytes32 lastRoot)
        internal
        pure
        returns (uint256, bytes32)
    {
        (uint256 updatedElementsCount, bytes32 newRoot,) = doAppend(elem, peaks, lastElementsCount, lastRoot);

        return (updatedElementsCount, newRoot);
    }

    ///
    /// Same as `append` but also returns the updated peaks
    ///
    function appendWithPeaksRetrieval(bytes32 elem, bytes32[] memory peaks, uint256 lastElementsCount, bytes32 lastRoot)
        internal
        pure
        returns (uint256, bytes32, bytes32[] memory)
    {
        (uint256 updatedElementsCount, bytes32 newRoot, bytes32[] memory updatedPeaks) =
            doAppend(elem, peaks, lastElementsCount, lastRoot);

        return (updatedElementsCount, newRoot, updatedPeaks);
    }

    ///
    /// @param elems Elements to append (in order)
    /// @param peaks The latest peaks
    /// @param lastElementsCount The latest elements count
    /// @param lastRoot The latest tree root hash
    /// @return The newest elements count and the newest tree root hash
    ///
    function multiAppend(bytes32[] memory elems, bytes32[] memory peaks, uint256 lastElementsCount, bytes32 lastRoot)
        internal
        pure
        returns (uint256, bytes32)
    {
        uint256 elementsCount = lastElementsCount;
        bytes32 root = lastRoot;
        bytes32[] memory updatedPeaks = peaks;

        for (uint256 i = 0; i < elems.length; ++i) {
            (elementsCount, root, updatedPeaks) = appendWithPeaksRetrieval(elems[i], updatedPeaks, elementsCount, root);
        }
        return (elementsCount, root);
    }

    ///
    /// Same as `multiAppend` but also returns the updated peaks
    ///
    function multiAppendWithPeaksRetrieval(
        bytes32[] memory elems,
        bytes32[] memory peaks,
        uint256 lastElementsCount,
        bytes32 lastRoot
    ) internal pure returns (uint256, bytes32, bytes32[] memory) {
        uint256 elementsCount = lastElementsCount;
        bytes32 root = lastRoot;
        bytes32[] memory updatedPeaks = peaks;

        for (uint256 i = 0; i < elems.length; ++i) {
            (elementsCount, root, updatedPeaks) = appendWithPeaksRetrieval(elems[i], updatedPeaks, elementsCount, root);
        }
        return (elementsCount, root, updatedPeaks);
    }

    ///
    /// @notice Efficient version of `multiAppend` that takes in all the precomputed peaks
    /// @param elems Elements to append (in order)
    /// @param allPeaks All the precomputed peaks computed off-chain (more gas efficient)
    /// @param lastElementsCount The latest elements count
    /// @param lastRoot The latest tree root hash
    /// @return The newest elements count and the newest tree root hash
    ///
    function multiAppendWithPrecomputedPeaks(
        bytes32[] memory elems,
        bytes32[][] memory allPeaks,
        uint256 lastElementsCount,
        bytes32 lastRoot
    ) internal pure returns (uint256, bytes32) {
        uint256 elementsCount = lastElementsCount;
        bytes32 root = lastRoot;

        for (uint256 i = 0; i < elems.length; ++i) {
            (elementsCount, root) = append(elems[i], allPeaks[i], elementsCount, root);
        }
        return (elementsCount, root);
    }

    ///
    /// @notice Verify a Merkle inclusion proof
    /// @dev Reverts if the proof is invalid
    /// @param proof The Merkle inclusion proof
    /// @param peaks The peaks at the time of inclusion
    /// @param elementsCount The element count at the time of inclusion
    /// @param root The tree root hash at the time of inclusion
    ///
    function verifyProof(
        uint256 index,
        bytes32 value,
        bytes32[] memory proof,
        bytes32[] memory peaks,
        uint256 elementsCount,
        bytes32 root
    ) internal pure {
        if (index > elementsCount) {
            revert IndexOutOfBounds();
        }
        bytes32 computedRoot = computeRoot(peaks, bytes32(elementsCount));
        if (computedRoot != root) {
            revert InvalidRoot();
        }

        bytes32 topPeak = getProofTopPeak(0, value, index, proof);

        bool isValid = StatelessMmrHelpers.arrayContains(topPeak, peaks);
        if (!isValid) {
            revert InvalidProof();
        }
    }

    ///   _    _      _                   ______                _   _
    ///  | |  | |    | |                 |  ____|              | | (_)
    ///  | |__| | ___| |_ __   ___ _ __  | |__ _   _ _ __   ___| |_ _  ___  _ __  ___
    ///  |  __  |/ _ \ | '_ \ / _ \ '__| |  __| | | | '_ \ / __| __| |/ _ \| '_ \/ __|
    ///  | |  | |  __/ | |_) |  __/ |    | |  | |_| | | | | (__| |_| | (_) | | | \__ \
    ///  |_|  |_|\___|_| .__/ \___|_|    |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
    ///                | |
    ///                |_|

    ///
    /// @notice Computes the root hash of the given peaks and tree size
    /// @param peaks Peaks to compute the root from
    /// @param size Tree size to to compute the root from
    /// @return The root hash of the following peaks and tree size
    ///
    function computeRoot(bytes32[] memory peaks, bytes32 size) internal pure returns (bytes32) {
        bytes32 baggedPeaks = bagPeaks(peaks);

        return Field.toBytes32(Poseidon2Lib.hash_2(Field.toField(size), Field.toField(baggedPeaks)));
    }

    ///
    /// @notice Bag the peaks: recursively hashing peaks together to form a single hash
    /// @param peaks The peaks to bag
    /// @return The bagged peaks
    ///
    function bagPeaks(bytes32[] memory peaks) internal pure returns (bytes32) {
        if (peaks.length < 1) {
            revert InvalidPeaksArrayLength();
        }
        if (peaks.length == 1) {
            return peaks[0];
        }

        uint256 len = peaks.length;
        bytes32 root0 =
            Field.toBytes32(Poseidon2Lib.hash_2(Field.toField(peaks[len - 2]), Field.toField(peaks[len - 1])));
        bytes32[] memory reversedPeaks = new bytes32[](len - 2);
        for (uint256 i = 0; i < len - 2; i++) {
            reversedPeaks[i] = peaks[len - 3 - i];
        }

        bytes32 bags = root0;
        for (uint256 i = 0; i < reversedPeaks.length; i++) {
            bags = Field.toBytes32(Poseidon2Lib.hash_2(Field.toField(reversedPeaks[i]), Field.toField(bags)));
        }
        return bags;
    }

    function doAppend(bytes32 elem, bytes32[] memory peaks, uint256 lastElementsCount, bytes32 lastRoot)
        internal
        pure
        returns (uint256, bytes32, bytes32[] memory)
    {
        uint256 elementsCount = lastElementsCount + 1;
        if (lastElementsCount == 0) {
            bytes32 root0 = elem;
            bytes32 firstRoot = Field.toBytes32(Poseidon2Lib.hash_2(Field.toField(uint256(1)), Field.toField(root0)));
            bytes32[] memory newPeaks = new bytes32[](1);
            newPeaks[0] = root0;
            return (elementsCount, firstRoot, newPeaks);
        }

        uint256 leafCount = StatelessMmrHelpers.mmrSizeToLeafCount(elementsCount - 1);
        uint256 numberOfPeaks = StatelessMmrHelpers.countOnes(leafCount);
        if (peaks.length != numberOfPeaks) {
            revert InvalidPeaksArrayLength();
        }

        bytes32 computedRoot = computeRoot(peaks, bytes32(lastElementsCount));
        if (computedRoot != lastRoot) {
            revert InvalidRoot();
        }

        bytes32[] memory appendPeaks = StatelessMmrHelpers.newArrWithElem(peaks, elem);

        uint256 appendNoMerges = StatelessMmrHelpers.leafCountToAppendNoMerges(leafCount);
        bytes32[] memory updatedPeaks = appendPerformMerging(appendPeaks, appendNoMerges);

        uint256 updatedElementsCount = elementsCount + appendNoMerges;

        bytes32 newRoot = computeRoot(updatedPeaks, bytes32(updatedElementsCount));
        return (updatedElementsCount, newRoot, updatedPeaks);
    }

    function appendPerformMerging(bytes32[] memory peaks, uint256 noMerges) internal pure returns (bytes32[] memory) {
        uint256 peaksLen = peaks.length;
        bytes32 accHash = peaks[peaksLen - 1];
        for (uint256 i = 0; i < noMerges; i++) {
            bytes32 hash = peaks[peaksLen - i - 2];
            accHash = Field.toBytes32(Poseidon2Lib.hash_2(Field.toField(hash), Field.toField(accHash)));
        }
        bytes32[] memory newPeaks = new bytes32[](peaksLen - noMerges);
        for (uint256 i = 0; i < peaksLen - noMerges - 1; i++) {
            newPeaks[i] = peaks[i];
        }
        newPeaks[peaksLen - noMerges - 1] = accHash;

        return newPeaks;
    }

    function getProofTopPeak(uint256 height, bytes32 hash, uint256 elementsCount, bytes32[] memory proof)
        internal
        pure
        returns (bytes32)
    {
        uint256 leafIndex = StatelessMmrHelpers.mmrIndexToLeafIndex(elementsCount);
        for (uint256 i = 0; i < proof.length; ++i) {
            bytes32 currentSibling = proof[i];

            bool isRightChild = leafIndex % 2 == 1;
            if (isRightChild) {
                bytes32 hashed =
                    Field.toBytes32(Poseidon2Lib.hash_2(Field.toField(currentSibling), Field.toField(hash)));
                elementsCount += 1;

                hash = hashed;
            } else {
                bytes32 hashed =
                    Field.toBytes32(Poseidon2Lib.hash_2(Field.toField(hash), Field.toField(currentSibling)));

                elementsCount += 2 << height;

                hash = hashed;
            }
            ++height;
            leafIndex /= 2;
        }
        return hash;
    }
}
