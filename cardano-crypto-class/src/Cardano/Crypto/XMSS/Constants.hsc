{-# LANGUAGE DataKinds #-}
-- | Sizes for the XMSS-SHA2_10_192 benchmark mock as compiled in @cbits/cardano_xmss_mock.h@.
module Cardano.Crypto.XMSS.Constants (
    XMSS_MOCK_SEEDBYTES,
    XMSS_MOCK_PUBLICKEYBYTES,
    XMSS_MOCK_SECRETKEYBYTES,
    XMSS_MOCK_SIGBYTES,
    XMSS_MOCK_SIGNKEYBYTES,
    xmssMockSignKeySeedOffset,
    xmssMockSignKeySkOffset,
    xmssMockSignKeyPkOffset,
    ) where

#include "cardano_xmss_mock.h"

-- | Key generation seed, 32 octets, expanded to the scheme's 3n = 72 with SHA-256.
type XMSS_MOCK_SEEDBYTES = #{const CARDANO_XMSS_MOCK_SEEDBYTES}

-- | XMSS-SHA2_10_192 public key (root || PUB_SEED), 48 octets.
type XMSS_MOCK_PUBLICKEYBYTES = #{const CARDANO_XMSS_MOCK_PUBLICKEYBYTES}

-- | XMSS-SHA2_10_192 private key with BDS state, 1053 octets.
type XMSS_MOCK_SECRETKEYBYTES = #{const CARDANO_XMSS_MOCK_SECRETKEYBYTES}

-- | XMSS-SHA2_10_192 signature, 1492 octets.
type XMSS_MOCK_SIGBYTES = #{const CARDANO_XMSS_MOCK_SIGBYTES}

-- | In-memory sign key layout used by this package: @seed || sk || pk@.
type XMSS_MOCK_SIGNKEYBYTES = #{const CARDANO_XMSS_MOCK_SIGNKEYBYTES}

xmssMockSignKeySeedOffset :: Int
xmssMockSignKeySeedOffset = #{const CARDANO_XMSS_MOCK_SIGNKEY_SEED_OFFSET}

xmssMockSignKeySkOffset :: Int
xmssMockSignKeySkOffset = #{const CARDANO_XMSS_MOCK_SIGNKEY_SK_OFFSET}

xmssMockSignKeyPkOffset :: Int
xmssMockSignKeyPkOffset = #{const CARDANO_XMSS_MOCK_SIGNKEY_PK_OFFSET}
