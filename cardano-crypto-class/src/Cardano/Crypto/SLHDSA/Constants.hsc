{-# LANGUAGE DataKinds #-}
-- | Sizes for SLH-DSA bb-6 as compiled in @cbits/cardano_slhdsa_bb6.h@.
module Cardano.Crypto.SLHDSA.Constants (
    SLHDSA_BB6_SEEDBYTES,
    SLHDSA_BB6_PUBLICKEYBYTES,
    SLHDSA_BB6_SECRETKEYBYTES,
    SLHDSA_BB6_SIGBYTES,
    SLHDSA_BB6_SIGNKEYBYTES,
    slhdsaBb6SignKeySeedOffset,
    slhdsaBb6SignKeySkOffset,
    slhdsaBb6SignKeyPkOffset,
    ) where

#include "cardano_slhdsa_bb6.h"

-- | Key generation seed, 32 octets, expanded to the scheme's 48 with SHA-256.
type SLHDSA_BB6_SEEDBYTES = #{const CARDANO_SLHDSA_BB6_SEEDBYTES}

-- | bb-6 public key (PK.seed || root), 32 octets.
type SLHDSA_BB6_PUBLICKEYBYTES = #{const CARDANO_SLHDSA_BB6_PUBLICKEYBYTES}

-- | bb-6 private key (SK.seed || SK.prf || PK), 64 octets.
type SLHDSA_BB6_SECRETKEYBYTES = #{const CARDANO_SLHDSA_BB6_SECRETKEYBYTES}

-- | bb-6 signature, 3360 octets.
type SLHDSA_BB6_SIGBYTES = #{const CARDANO_SLHDSA_BB6_SIGBYTES}

-- | In-memory sign key layout used by this package: @seed || sk || pk@.
type SLHDSA_BB6_SIGNKEYBYTES = #{const CARDANO_SLHDSA_BB6_SIGNKEYBYTES}

slhdsaBb6SignKeySeedOffset :: Int
slhdsaBb6SignKeySeedOffset = #{const CARDANO_SLHDSA_BB6_SIGNKEY_SEED_OFFSET}

slhdsaBb6SignKeySkOffset :: Int
slhdsaBb6SignKeySkOffset = #{const CARDANO_SLHDSA_BB6_SIGNKEY_SK_OFFSET}

slhdsaBb6SignKeyPkOffset :: Int
slhdsaBb6SignKeyPkOffset = #{const CARDANO_SLHDSA_BB6_SIGNKEY_PK_OFFSET}
