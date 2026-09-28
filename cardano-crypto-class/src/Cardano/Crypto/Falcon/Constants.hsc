{-# LANGUAGE DataKinds #-}
-- | Sizes for Falcon-512 as compiled in @cbits/cardano_falcon512.h@.
module Cardano.Crypto.Falcon.Constants (
    FALCON512_SEEDBYTES,
    FALCON512_PUBLICKEYBYTES,
    FALCON512_SECRETKEYBYTES,
    FALCON512_SIGBYTES,
    FALCON512_SIGNKEYBYTES,
    falcon512SignKeySeedOffset,
    falcon512SignKeySkOffset,
    falcon512SignKeyPkOffset,
    ) where

#include "cardano_falcon512.h"

-- | Key generation seed, 32 octets, absorbed into the keygen SHAKE256.
type FALCON512_SEEDBYTES = #{const CARDANO_FALCON512_SEEDBYTES}

-- | Falcon-512 public key, 897 octets (PQClean encoding).
type FALCON512_PUBLICKEYBYTES = #{const CARDANO_FALCON512_PUBLICKEYBYTES}

-- | Falcon-512 private key, 1281 octets (PQClean encoding).
type FALCON512_SECRETKEYBYTES = #{const CARDANO_FALCON512_SECRETKEYBYTES}

-- | Falcon-512 padded signature, 666 octets.
type FALCON512_SIGBYTES = #{const CARDANO_FALCON512_SIGBYTES}

-- | In-memory sign key layout used by this package: @seed || sk || pk@.
type FALCON512_SIGNKEYBYTES = #{const CARDANO_FALCON512_SIGNKEYBYTES}

falcon512SignKeySeedOffset :: Int
falcon512SignKeySeedOffset = #{const CARDANO_FALCON512_SIGNKEY_SEED_OFFSET}

falcon512SignKeySkOffset :: Int
falcon512SignKeySkOffset = #{const CARDANO_FALCON512_SIGNKEY_SK_OFFSET}

falcon512SignKeyPkOffset :: Int
falcon512SignKeyPkOffset = #{const CARDANO_FALCON512_SIGNKEY_PK_OFFSET}
