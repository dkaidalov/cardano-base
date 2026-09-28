{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DataKinds #-}

-- | FFI bindings to the ML-DSA-44 wrapper in @cbits/cardano_mldsa44.c@,
-- which is a thin layer over the vendored mldsa-native sources in
-- @cbits/mldsa-native@.
module Cardano.Crypto.MLDSA.C (
  -- * Key generation
  c_cardano_mldsa44_signkey_from_seed,

  -- * Signing and verification
  c_cardano_mldsa44_sign,
  c_cardano_mldsa44_verify,

  -- * Constants
  MLDSA44_SEEDBYTES,
  MLDSA44_PUBLICKEYBYTES,
  MLDSA44_SECRETKEYBYTES,
  MLDSA44_SIGBYTES,
  MLDSA44_SIGNKEYBYTES,
  mldsa44SignKeySeedOffset,
  mldsa44SignKeySkOffset,
  mldsa44SignKeyPkOffset,
) where

import Data.Word (Word8)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr)

import Cardano.Crypto.MLDSA.Constants
import Cardano.Foreign (SizedPtr (..))

-- | @int cardano_mldsa44_signkey_from_seed(uint8_t *signkey, const uint8_t *seed);@
--
-- Expands a 32-octet seed into the in-memory sign key @seed || sk || pk@.
-- Returns 0 on success.
foreign import capi unsafe "cardano_mldsa44.h cardano_mldsa44_signkey_from_seed"
  c_cardano_mldsa44_signkey_from_seed ::
    SizedPtr MLDSA44_SIGNKEYBYTES -> SizedPtr MLDSA44_SEEDBYTES -> IO CInt

-- | @int cardano_mldsa44_sign(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *signkey);@
--
-- Deterministic ML-DSA-44 (FIPS 204 Algorithm 2 with @rnd = 0@) over @m@
-- with an empty context string. Returns 0 on success.
foreign import capi unsafe "cardano_mldsa44.h cardano_mldsa44_sign"
  c_cardano_mldsa44_sign ::
    SizedPtr MLDSA44_SIGBYTES -> Ptr Word8 -> CSize -> SizedPtr MLDSA44_SIGNKEYBYTES -> IO CInt

-- | @int cardano_mldsa44_verify(const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pk);@
--
-- FIPS 204 Algorithm 3 with an empty context string. Returns 0 if the
-- signature is valid.
foreign import capi unsafe "cardano_mldsa44.h cardano_mldsa44_verify"
  c_cardano_mldsa44_verify ::
    SizedPtr MLDSA44_SIGBYTES -> Ptr Word8 -> CSize -> SizedPtr MLDSA44_PUBLICKEYBYTES -> IO CInt
