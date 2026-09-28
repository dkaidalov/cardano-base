{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
-- See the note on 'unsafeDupablePerformIO' in "Cardano.Crypto.DSIGN.Ed25519":
-- without -fno-full-laziness, FFI calls wrapped in unsafeDupablePerformIO can
-- float out of lambdas and become nondeterministic under -N.
{-# OPTIONS_GHC -fno-full-laziness #-}

-- | BENCHMARK-ONLY stateful leaf: XMSS-SHA2_10_192 (RFC 8391, SP 800-208)
-- over the vendored XMSS reference implementation in @cbits/xmss-reference@,
-- with BDS tree traversal.
--
-- XMSS is stateful: each signature consumes one of the 2^10 one-time keys,
-- and the index and traversal state live inside the secret key. The DSIGN
-- classes cannot express that: 'signDSIGN' is pure and 'signDSIGNM' returns
-- only a signature. This instance therefore
--
-- * keeps the state inside the mlocked sign key and advances it in
--   'signDSIGNM' (a hidden mutation of the key, which is what makes the
--   scheme usable for the KES compositions and their benchmarks);
-- * signs on a copy of the state in 'signDSIGN', so the pure API reuses the
--   current one-time key on every call, which is insecure;
-- * serialises only the seed, so a deserialised key restarts at index 0 and
--   would reuse keys.
--
-- A key yields 1023 signatures; the 1024th is refused ('signDSIGNM' then
-- throws). None of this is fixable inside the current classes; the instance
-- exists to measure what a stateful leaf costs in this composition, next to
-- the stateless ones. Do not use it for anything else.
--
-- The in-memory sign key is @seed || sk || pk@ (32 + 1053 + 48 octets). Key
-- generation builds the whole 2^10-leaf tree (about a quarter of a second
-- with portable SHA-256).
module Cardano.Crypto.DSIGN.XmssMock (
  XmssMockDSIGN,
  SigDSIGN (..),
  SignKeyDSIGN (..),
  SignKeyDSIGNM (..),
  VerKeyDSIGN (..),
)
where

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  fixedSize,
  guardFixedSized,
 )
import Control.DeepSeq (NFData (..), rwhnf)
import Control.Monad (unless, when, (<$!>))
import Control.Monad.Class.MonadThrow (MonadThrow (..), throwIO)
import qualified Data.ByteString as BS
import Data.Proxy
import Foreign.C.Types (CInt, CSize)
import Foreign.Ptr (castPtr, plusPtr)
import GHC.Generics (Generic)
import GHC.TypeLits (ErrorMessage (..), TypeError)
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.DirectSerialise
import Cardano.Crypto.Libsodium (
  MLockedSizedBytes,
  mlsbCopyWith,
  mlsbFinalize,
  mlsbFromByteStringCheckWith,
  mlsbNewWith,
  mlsbToByteString,
  mlsbUseAsSizedPtr,
 )
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Libsodium.Memory.Internal (unsafeIOToMonadST)
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreate,
  psbCreateSized,
  psbCreateSizedResult,
  psbToByteString,
  psbUseAsCPtrLen,
  psbUseAsSizedPtr,
 )
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (SignableRepresentation (..))
import Cardano.Crypto.XMSS.C
import Cardano.Foreign

data XmssMockDSIGN

instance NoThunks (VerKeyDSIGN XmssMockDSIGN)
instance NoThunks (SignKeyDSIGN XmssMockDSIGN)
instance NoThunks (SigDSIGN XmssMockDSIGN)

deriving via
  (MLockedSizedBytes XMSS_MOCK_SIGNKEYBYTES)
  instance
    NoThunks (SignKeyDSIGNM XmssMockDSIGN)

instance NFData (SignKeyDSIGNM XmssMockDSIGN) where
  rnf = rwhnf

--
-- Sign key layout helpers
--

-- | The seed slot of an in-memory sign key.
signKeySeedPtr :: SizedPtr XMSS_MOCK_SIGNKEYBYTES -> SizedPtr XMSS_MOCK_SEEDBYTES
signKeySeedPtr (SizedPtr p) = SizedPtr (p `plusPtr` xmssMockSignKeySeedOffset)

-- | The public key slot of an in-memory sign key.
signKeyPkPtr :: SizedPtr XMSS_MOCK_SIGNKEYBYTES -> SizedPtr XMSS_MOCK_PUBLICKEYBYTES
signKeyPkPtr (SizedPtr p) = SizedPtr (p `plusPtr` xmssMockSignKeyPkOffset)

--
-- Error reporting. The XMSS reference reports failures through its return code,
-- not errno.
--

xmssError :: String -> String -> CInt -> IOError
xmssError contextDesc cFunName rc =
  userError (contextDesc ++ ": " ++ cFunName ++ " failed with code " ++ show rc)

-- | Run an FFI call returning a status code and throw on a non-zero result.
xmssOrThrow :: String -> String -> IO CInt -> IO ()
xmssOrThrow contextDesc cFunName action = do
  rc <- action
  unless (rc == 0) $ ioError (xmssError contextDesc cFunName rc)

-- | Throw on a non-zero status code, outside of ST.
throwOnFailure :: MonadThrow m => String -> String -> CInt -> m ()
throwOnFailure contextDesc cFunName rc =
  unless (rc == 0) $ throwIO (xmssError contextDesc cFunName rc)

instance DSIGNAlgorithm XmssMockDSIGN where
  type SeedSizeDSIGN XmssMockDSIGN = XMSS_MOCK_SEEDBYTES

  --
  -- Key and signature types
  --

  newtype VerKeyDSIGN XmssMockDSIGN
    = VerKeyXmssMockDSIGN (PinnedSizedBytes XMSS_MOCK_PUBLICKEYBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  -- The in-memory representation is @seed || sk || pk@; the declared
  -- (serialised) sign key size is the seed size, see 'FixedSizeCodec' below.
  newtype SignKeyDSIGN XmssMockDSIGN
    = SignKeyXmssMockDSIGN (PinnedSizedBytes XMSS_MOCK_SIGNKEYBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  newtype SigDSIGN XmssMockDSIGN
    = SigXmssMockDSIGN (PinnedSizedBytes XMSS_MOCK_SIGBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGN _ = "xmss_sha2_10_192_mock"

  deriveVerKeyDSIGN (SignKeyXmssMockDSIGN sk) =
    VerKeyXmssMockDSIGN $
      unsafeDupablePerformIO $
        psbUseAsSizedPtr sk $ \skPtr ->
          psbCreateSized $ \pkPtr ->
            memcpySized pkPtr (signKeyPkPtr skPtr)

  --
  -- Core algorithm operations
  --

  type Signable XmssMockDSIGN = SignableRepresentation

  signDSIGN () a (SignKeyXmssMockDSIGN sk) =
    let bs = getSignableRepresentation a
     in SigXmssMockDSIGN $
          unsafeDupablePerformIO $
            BS.useAsCStringLen bs $ \(ptr, len) ->
              psbUseAsSizedPtr sk $ \skPtr ->
                psbCreateSized $ \sigPtr ->
                  xmssOrThrow "signDSIGN @XmssMockDSIGN" "cardano_xmss_mock_sign_copy" $
                    c_cardano_xmss_mock_sign_copy sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) skPtr

  verifyDSIGN () (VerKeyXmssMockDSIGN vk) a (SigXmssMockDSIGN sig) =
    let bs = getSignableRepresentation a
     in unsafeDupablePerformIO $
          BS.useAsCStringLen bs $ \(ptr, len) ->
            psbUseAsSizedPtr vk $ \vkPtr ->
              psbUseAsSizedPtr sig $ \sigPtr -> do
                rc <- c_cardano_xmss_mock_verify sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) vkPtr
                return $
                  if rc == 0
                    then Right ()
                    else Left "Verification failed"

  --
  -- Key generation
  --
  genKeyDSIGN seed =
    SignKeyXmssMockDSIGN $
      let (sb, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @XmssMockDSIGN)) seed
       in unsafeDupablePerformIO $
            psbCreateSized $ \skPtr ->
              BS.useAsCStringLen sb $ \(seedPtr, _) ->
                xmssOrThrow "genKeyDSIGN @XmssMockDSIGN" "cardano_xmss_mock_signkey_from_seed" $
                  c_cardano_xmss_mock_signkey_from_seed skPtr (SizedPtr . castPtr $ seedPtr)

instance DSIGNMAlgorithm XmssMockDSIGN where
  newtype SignKeyDSIGNM XmssMockDSIGN
    = SignKeyXmssMockDSIGNM (MLockedSizedBytes XMSS_MOCK_SIGNKEYBYTES)
    deriving (Show)

  deriveVerKeyDSIGNM (SignKeyXmssMockDSIGNM sk) =
    VerKeyXmssMockDSIGN <$!> do
      mlsbUseAsSizedPtr sk $ \skPtr ->
        psbCreateSized $ \pkPtr ->
          unsafeIOToMonadST $ memcpySized pkPtr (signKeyPkPtr skPtr)

  signDSIGNM () a (SignKeyXmssMockDSIGNM sk) =
    let bs = getSignableRepresentation a
     in do
          (psb, rc) <-
            mlsbUseAsSizedPtr sk $ \skPtr ->
              psbCreateSizedResult $ \sigPtr ->
                unsafeIOToMonadST $
                  BS.useAsCStringLen bs $ \(ptr, len) ->
                    c_cardano_xmss_mock_sign_advance sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) skPtr
          throwOnFailure "signDSIGNM @XmssMockDSIGN" "cardano_xmss_mock_sign_advance" rc
          return $! SigXmssMockDSIGN psb

  --
  -- Key generation
  --
  {-# NOINLINE genKeyDSIGNMWith #-}
  genKeyDSIGNMWith allocator seed = do
    sk <- mlsbNewWith allocator
    rc <-
      mlsbUseAsSizedPtr sk $ \skPtr ->
        mlockedSeedUseAsSizedPtr seed $ \seedPtr ->
          unsafeIOToMonadST $ c_cardano_xmss_mock_signkey_from_seed skPtr seedPtr
    when (rc /= 0) $ mlsbFinalize sk
    throwOnFailure "genKeyDSIGNM @XmssMockDSIGN" "cardano_xmss_mock_signkey_from_seed" rc
    return $! SignKeyXmssMockDSIGNM sk

  cloneKeyDSIGNMWith allocator (SignKeyXmssMockDSIGNM sk) =
    SignKeyXmssMockDSIGNM <$!> mlsbCopyWith allocator sk

  getSeedDSIGNMWith allocator _ (SignKeyXmssMockDSIGNM sk) = do
    seed <- mlockedSeedNewWith allocator
    mlsbUseAsSizedPtr sk $ \skPtr ->
      mlockedSeedUseAsSizedPtr seed $ \seedPtr ->
        unsafeIOToMonadST $ memcpySized seedPtr (signKeySeedPtr skPtr)
    return seed

  --
  -- Secure forgetting
  --
  forgetSignKeyDSIGNMWith _ (SignKeyXmssMockDSIGNM sk) = mlsbFinalize sk

instance UnsoundDSIGNMAlgorithm XmssMockDSIGN where
  --
  -- Ser/deser (dangerous - do not use in production code)
  --
  rawSerialiseSignKeyDSIGNM sk = do
    seed <- getSeedDSIGNM (Proxy @XmssMockDSIGN) sk
    -- Copies the seed to the unprotected Haskell heap, see 'mlsbToByteString'.
    raw <- mlsbToByteString . mlockedSeedMLSB $ seed
    mlockedSeedFinalize seed
    return raw

  rawDeserialiseSignKeyDSIGNMWith allocator raw = do
    mseed <- fmap MLockedSeed <$> mlsbFromByteStringCheckWith allocator raw
    case mseed of
      Nothing -> return Nothing
      Just seed -> do
        sk <- Just <$> genKeyDSIGNMWith allocator seed
        mlockedSeedFinalize seed
        return sk

instance FixedSizeCodec (VerKeyDSIGN XmssMockDSIGN) where
  type FixedSize (VerKeyDSIGN XmssMockDSIGN) = XMSS_MOCK_PUBLICKEYBYTES
  rawEncodeFixedSized (VerKeyXmssMockDSIGN vk) = psbToByteString vk
  rawDecodeFixedSized bs = VerKeyXmssMockDSIGN <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyDSIGN XmssMockDSIGN) where
  -- \| Only the 32-octet seed is serialised; the key is regenerated on
  -- deserialisation and restarts at one-time index 0 (see the module
  -- header for why this is only acceptable in a benchmark mock).
  type FixedSize (SignKeyDSIGN XmssMockDSIGN) = XMSS_MOCK_SEEDBYTES
  rawEncodeFixedSized (SignKeyXmssMockDSIGN sk) =
    BS.take (fromIntegral @Word @Int $ seedSizeDSIGN (Proxy @XmssMockDSIGN)) $
      BS.drop xmssMockSignKeySeedOffset $
        psbToByteString sk
  rawDecodeFixedSized bs = guardFixedSized bs $ pure . genKeyDSIGN $ mkSeedFromBytes bs
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SigDSIGN XmssMockDSIGN) where
  type FixedSize (SigDSIGN XmssMockDSIGN) = XMSS_MOCK_SIGBYTES
  rawEncodeFixedSized (SigXmssMockDSIGN sig) = psbToByteString sig
  rawDecodeFixedSized bs = SigXmssMockDSIGN <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance ToCBOR (VerKeyDSIGN XmssMockDSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN XmssMockDSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN XmssMockDSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN XmssMockDSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN XmssMockDSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN XmssMockDSIGN) where
  fromCBOR = decodeFixedSized

instance
  TypeError ('Text "CBOR encoding would violate mlocking guarantees") =>
  ToCBOR (SignKeyDSIGNM XmssMockDSIGN)
  where
  toCBOR = error "unsupported"
  encodedSizeExpr _ = error "unsupported"

instance
  TypeError ('Text "CBOR decoding would violate mlocking guarantees") =>
  FromCBOR (SignKeyDSIGNM XmssMockDSIGN)
  where
  fromCBOR = error "unsupported"

instance DirectSerialise (SignKeyDSIGNM XmssMockDSIGN) where
  -- /Note:/ Only the 32-octet seed is serialised; @sk || pk@ is regenerated
  -- from it on deserialisation.
  directSerialise push sk = do
    bracket
      (getSeedDSIGNM (Proxy @XmssMockDSIGN) sk)
      mlockedSeedFinalize
      ( \seed -> mlockedSeedUseAsCPtr seed $ \ptr ->
          push
            (castPtr ptr)
            (fromIntegral @Word @CSize $ seedSizeDSIGN (Proxy @XmssMockDSIGN))
      )

instance DirectDeserialise (SignKeyDSIGNM XmssMockDSIGN) where
  directDeserialise pull = do
    bracket
      mlockedSeedNew
      mlockedSeedFinalize
      ( \seed -> do
          mlockedSeedUseAsCPtr seed $ \ptr -> do
            pull
              (castPtr ptr)
              (fromIntegral @Word @CSize $ seedSizeDSIGN (Proxy @XmssMockDSIGN))
          genKeyDSIGNM seed
      )

instance DirectSerialise (VerKeyDSIGN XmssMockDSIGN) where
  directSerialise push (VerKeyXmssMockDSIGN psb) = do
    psbUseAsCPtrLen psb $ \ptr _ ->
      push
        (castPtr ptr)
        (fromIntegral @Word @CSize $ fixedSize (Proxy @(VerKeyDSIGN XmssMockDSIGN)))

instance DirectDeserialise (VerKeyDSIGN XmssMockDSIGN) where
  directDeserialise pull = do
    psb <- psbCreate $ \ptr ->
      pull
        (castPtr ptr)
        (fromIntegral @Word @CSize $ fixedSize (Proxy @(VerKeyDSIGN XmssMockDSIGN)))
    return $! VerKeyXmssMockDSIGN psb
