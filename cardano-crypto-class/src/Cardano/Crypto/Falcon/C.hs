{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DataKinds #-}

-- | FFI bindings to the Falcon-512 wrapper in @cbits/cardano_falcon512.c@,
-- which is a thin layer over the vendored PQClean falcon-padded-512 sources in
-- @cbits/falcon-padded-512@.
module Cardano.Crypto.Falcon.C (
  -- * Key generation
  c_cardano_falcon512_signkey_from_seed,

  -- * Signing and verification
  c_cardano_falcon512_sign,
  c_cardano_falcon512_verify,

  -- * Constants
  FALCON512_SEEDBYTES,
  FALCON512_PUBLICKEYBYTES,
  FALCON512_SECRETKEYBYTES,
  FALCON512_SIGBYTES,
  FALCON512_SIGNKEYBYTES,
  falcon512SignKeySeedOffset,
  falcon512SignKeySkOffset,
  falcon512SignKeyPkOffset,
) where

import Data.Word (Word8)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr)

import Cardano.Crypto.Falcon.Constants
import Cardano.Foreign (SizedPtr (..))

-- | @int cardano_falcon512_signkey_from_seed(uint8_t *signkey, const uint8_t *seed);@
--
-- Expands a 32-octet seed into the in-memory sign key @seed || sk || pk@.
-- Returns 0 on success.
foreign import capi unsafe "cardano_falcon512.h cardano_falcon512_signkey_from_seed"
  c_cardano_falcon512_signkey_from_seed ::
    SizedPtr FALCON512_SIGNKEYBYTES -> SizedPtr FALCON512_SEEDBYTES -> IO CInt

-- | @int cardano_falcon512_sign(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *signkey);@
--
-- Deterministic Falcon-512 (nonce and sampler seed derived from the key and @m@)
-- in the padded 666-octet encoding. Returns 0 on success.
foreign import capi unsafe "cardano_falcon512.h cardano_falcon512_sign"
  c_cardano_falcon512_sign ::
    SizedPtr FALCON512_SIGBYTES -> Ptr Word8 -> CSize -> SizedPtr FALCON512_SIGNKEYBYTES -> IO CInt

-- | @int cardano_falcon512_verify(const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pk);@
--
-- Falcon-512 verification of a padded signature. Returns 0 if the
-- signature is valid.
foreign import capi unsafe "cardano_falcon512.h cardano_falcon512_verify"
  c_cardano_falcon512_verify ::
    SizedPtr FALCON512_SIGBYTES -> Ptr Word8 -> CSize -> SizedPtr FALCON512_PUBLICKEYBYTES -> IO CInt
