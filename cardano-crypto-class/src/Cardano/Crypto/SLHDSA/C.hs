{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DataKinds #-}

-- | FFI bindings to the SLH-DSA bb-6 wrapper in @cbits/cardano_slhdsa_bb6.c@,
-- which is a thin layer over the vendored SPHINCS+ reference sources in
-- @cbits/sphincsplus-ref@.
module Cardano.Crypto.SLHDSA.C (
  -- * Key generation
  c_cardano_slhdsa_bb6_signkey_from_seed,

  -- * Signing and verification
  c_cardano_slhdsa_bb6_sign,
  c_cardano_slhdsa_bb6_verify,

  -- * Constants
  SLHDSA_BB6_SEEDBYTES,
  SLHDSA_BB6_PUBLICKEYBYTES,
  SLHDSA_BB6_SECRETKEYBYTES,
  SLHDSA_BB6_SIGBYTES,
  SLHDSA_BB6_SIGNKEYBYTES,
  slhdsaBb6SignKeySeedOffset,
  slhdsaBb6SignKeySkOffset,
  slhdsaBb6SignKeyPkOffset,
) where

import Data.Word (Word8)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr)

import Cardano.Crypto.SLHDSA.Constants
import Cardano.Foreign (SizedPtr (..))

-- | @int cardano_slhdsa_bb6_signkey_from_seed(uint8_t *signkey, const uint8_t *seed);@
--
-- Expands a 32-octet seed into the in-memory sign key @seed || sk || pk@.
-- Returns 0 on success.
foreign import capi unsafe "cardano_slhdsa_bb6.h cardano_slhdsa_bb6_signkey_from_seed"
  c_cardano_slhdsa_bb6_signkey_from_seed ::
    SizedPtr SLHDSA_BB6_SIGNKEYBYTES -> SizedPtr SLHDSA_BB6_SEEDBYTES -> IO CInt

-- | @int cardano_slhdsa_bb6_sign(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *signkey);@
--
-- Deterministic SLH-DSA (FIPS 205, @opt_rand = PK.seed@) over @m@
-- with the bb-6 parameter set. Returns 0 on success.
foreign import capi unsafe "cardano_slhdsa_bb6.h cardano_slhdsa_bb6_sign"
  c_cardano_slhdsa_bb6_sign ::
    SizedPtr SLHDSA_BB6_SIGBYTES -> Ptr Word8 -> CSize -> SizedPtr SLHDSA_BB6_SIGNKEYBYTES -> IO CInt

-- | @int cardano_slhdsa_bb6_verify(const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pk);@
--
-- SLH-DSA verification with the bb-6 parameter set. Returns 0 if the
-- signature is valid.
foreign import capi unsafe "cardano_slhdsa_bb6.h cardano_slhdsa_bb6_verify"
  c_cardano_slhdsa_bb6_verify ::
    SizedPtr SLHDSA_BB6_SIGBYTES -> Ptr Word8 -> CSize -> SizedPtr SLHDSA_BB6_PUBLICKEYBYTES -> IO CInt
