{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DataKinds #-}

-- | FFI bindings to the XMSS-SHA2_10_256 benchmark mock in
-- @cbits/cardano_xmss_mock.c@, a thin layer over the vendored XMSS reference
-- implementation in @cbits/xmss-reference@. See "Cardano.Crypto.DSIGN.XmssMock"
-- for what makes it a mock.
module Cardano.Crypto.XMSS.C (
  -- * Key generation
  c_cardano_xmss_mock_signkey_from_seed,

  -- * Signing and verification
  c_cardano_xmss_mock_sign_advance,
  c_cardano_xmss_mock_sign_copy,
  c_cardano_xmss_mock_verify,

  -- * Constants
  XMSS_MOCK_SEEDBYTES,
  XMSS_MOCK_PUBLICKEYBYTES,
  XMSS_MOCK_SECRETKEYBYTES,
  XMSS_MOCK_SIGBYTES,
  XMSS_MOCK_SIGNKEYBYTES,
  xmssMockSignKeySeedOffset,
  xmssMockSignKeySkOffset,
  xmssMockSignKeyPkOffset,
) where

import Data.Word (Word8)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr)

import Cardano.Crypto.XMSS.Constants
import Cardano.Foreign (SizedPtr (..))

-- | Expands a 32-octet seed into the in-memory sign key @seed || sk || pk@,
-- with the one-time index at 0. Returns 0 on success.
foreign import capi unsafe "cardano_xmss_mock.h cardano_xmss_mock_signkey_from_seed"
  c_cardano_xmss_mock_signkey_from_seed ::
    SizedPtr XMSS_MOCK_SIGNKEYBYTES -> SizedPtr XMSS_MOCK_SEEDBYTES -> IO CInt

-- | Signs with the current one-time key and advances the index and BDS state
-- inside the key. Returns 0 on success, -2 when the key is exhausted.
foreign import capi unsafe "cardano_xmss_mock.h cardano_xmss_mock_sign_advance"
  c_cardano_xmss_mock_sign_advance ::
    SizedPtr XMSS_MOCK_SIGBYTES -> Ptr Word8 -> CSize -> SizedPtr XMSS_MOCK_SIGNKEYBYTES -> IO CInt

-- | Signs with the current one-time key on a copy of the state; the key is
-- left unchanged, so repeated calls reuse the one-time key.
foreign import capi unsafe "cardano_xmss_mock.h cardano_xmss_mock_sign_copy"
  c_cardano_xmss_mock_sign_copy ::
    SizedPtr XMSS_MOCK_SIGBYTES -> Ptr Word8 -> CSize -> SizedPtr XMSS_MOCK_SIGNKEYBYTES -> IO CInt

-- | Returns 0 if the signature is valid.
foreign import capi unsafe "cardano_xmss_mock.h cardano_xmss_mock_verify"
  c_cardano_xmss_mock_verify ::
    SizedPtr XMSS_MOCK_SIGBYTES -> Ptr Word8 -> CSize -> SizedPtr XMSS_MOCK_PUBLICKEYBYTES -> IO CInt
