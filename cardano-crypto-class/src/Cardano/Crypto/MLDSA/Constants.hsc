{-# LANGUAGE DataKinds #-}
-- | Sizes for ML-DSA-44 as compiled in @cbits/cardano_mldsa44.h@.
module Cardano.Crypto.MLDSA.Constants (
    MLDSA44_SEEDBYTES,
    MLDSA44_PUBLICKEYBYTES,
    MLDSA44_SECRETKEYBYTES,
    MLDSA44_SIGBYTES,
    MLDSA44_SIGNKEYBYTES,
    mldsa44SignKeySeedOffset,
    mldsa44SignKeySkOffset,
    mldsa44SignKeyPkOffset,
    ) where

#include "cardano_mldsa44.h"

-- | FIPS 204 key generation seed (xi), 32 octets.
type MLDSA44_SEEDBYTES = #{const CARDANO_MLDSA44_SEEDBYTES}

-- | FIPS 204 ML-DSA-44 public key, 1312 octets.
type MLDSA44_PUBLICKEYBYTES = #{const CARDANO_MLDSA44_PUBLICKEYBYTES}

-- | FIPS 204 ML-DSA-44 expanded private key, 2560 octets.
type MLDSA44_SECRETKEYBYTES = #{const CARDANO_MLDSA44_SECRETKEYBYTES}

-- | FIPS 204 ML-DSA-44 signature, 2420 octets.
type MLDSA44_SIGBYTES = #{const CARDANO_MLDSA44_SIGBYTES}

-- | In-memory sign key layout used by this package: @seed || sk || pk@.
type MLDSA44_SIGNKEYBYTES = #{const CARDANO_MLDSA44_SIGNKEYBYTES}

mldsa44SignKeySeedOffset :: Int
mldsa44SignKeySeedOffset = #{const CARDANO_MLDSA44_SIGNKEY_SEED_OFFSET}

mldsa44SignKeySkOffset :: Int
mldsa44SignKeySkOffset = #{const CARDANO_MLDSA44_SIGNKEY_SK_OFFSET}

mldsa44SignKeyPkOffset :: Int
mldsa44SignKeyPkOffset = #{const CARDANO_MLDSA44_SIGNKEY_PK_OFFSET}
