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

-- | ML-DSA-44 (FIPS 204) digital signatures, over the vendored mldsa-native
-- sources in @cbits/mldsa-native@.
--
-- Signing is the deterministic variant of FIPS 204 Algorithm 2 (@rnd = 0@)
-- with an empty context string; verification is Algorithm 3 with an empty
-- context string.
--
-- The in-memory sign key is @seed || sk || pk@ (32 + 2560 + 1312 octets), so
-- that 'deriveVerKeyDSIGN' and 'getSeedDSIGNM' are plain copies. Only the
-- 32-octet seed is serialised; the expanded key is regenerated on
-- deserialisation, as for Ed25519.
module Cardano.Crypto.DSIGN.MLDSA44 (
  MLDSA44DSIGN,
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
import Cardano.Crypto.MLDSA.C
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
import Cardano.Foreign

data MLDSA44DSIGN

instance NoThunks (VerKeyDSIGN MLDSA44DSIGN)
instance NoThunks (SignKeyDSIGN MLDSA44DSIGN)
instance NoThunks (SigDSIGN MLDSA44DSIGN)

deriving via
  (MLockedSizedBytes MLDSA44_SIGNKEYBYTES)
  instance
    NoThunks (SignKeyDSIGNM MLDSA44DSIGN)

instance NFData (SignKeyDSIGNM MLDSA44DSIGN) where
  rnf = rwhnf

--
-- Sign key layout helpers
--

-- | The seed slot of an in-memory sign key.
signKeySeedPtr :: SizedPtr MLDSA44_SIGNKEYBYTES -> SizedPtr MLDSA44_SEEDBYTES
signKeySeedPtr (SizedPtr p) = SizedPtr (p `plusPtr` mldsa44SignKeySeedOffset)

-- | The public key slot of an in-memory sign key.
signKeyPkPtr :: SizedPtr MLDSA44_SIGNKEYBYTES -> SizedPtr MLDSA44_PUBLICKEYBYTES
signKeyPkPtr (SizedPtr p) = SizedPtr (p `plusPtr` mldsa44SignKeyPkOffset)

--
-- Error reporting. mldsa-native reports failures through its return code,
-- not errno.
--

mldsaError :: String -> String -> CInt -> IOError
mldsaError contextDesc cFunName rc =
  userError (contextDesc ++ ": " ++ cFunName ++ " failed with code " ++ show rc)

-- | Run an FFI call returning a status code and throw on a non-zero result.
mldsaOrThrow :: String -> String -> IO CInt -> IO ()
mldsaOrThrow contextDesc cFunName action = do
  rc <- action
  unless (rc == 0) $ ioError (mldsaError contextDesc cFunName rc)

-- | Throw on a non-zero status code, outside of ST.
throwOnFailure :: MonadThrow m => String -> String -> CInt -> m ()
throwOnFailure contextDesc cFunName rc =
  unless (rc == 0) $ throwIO (mldsaError contextDesc cFunName rc)

instance DSIGNAlgorithm MLDSA44DSIGN where
  type SeedSizeDSIGN MLDSA44DSIGN = MLDSA44_SEEDBYTES

  --
  -- Key and signature types
  --

  newtype VerKeyDSIGN MLDSA44DSIGN
    = VerKeyMLDSA44DSIGN (PinnedSizedBytes MLDSA44_PUBLICKEYBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  -- The in-memory representation is @seed || sk || pk@; the declared
  -- (serialised) sign key size is the seed size, see 'FixedSizeCodec' below.
  newtype SignKeyDSIGN MLDSA44DSIGN
    = SignKeyMLDSA44DSIGN (PinnedSizedBytes MLDSA44_SIGNKEYBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  newtype SigDSIGN MLDSA44DSIGN
    = SigMLDSA44DSIGN (PinnedSizedBytes MLDSA44_SIGBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGN _ = "mldsa44"

  deriveVerKeyDSIGN (SignKeyMLDSA44DSIGN sk) =
    VerKeyMLDSA44DSIGN $
      unsafeDupablePerformIO $
        psbUseAsSizedPtr sk $ \skPtr ->
          psbCreateSized $ \pkPtr ->
            memcpySized pkPtr (signKeyPkPtr skPtr)

  --
  -- Core algorithm operations
  --

  type Signable MLDSA44DSIGN = SignableRepresentation

  signDSIGN () a (SignKeyMLDSA44DSIGN sk) =
    let bs = getSignableRepresentation a
     in SigMLDSA44DSIGN $
          unsafeDupablePerformIO $
            BS.useAsCStringLen bs $ \(ptr, len) ->
              psbUseAsSizedPtr sk $ \skPtr ->
                psbCreateSized $ \sigPtr ->
                  mldsaOrThrow "signDSIGN @MLDSA44DSIGN" "cardano_mldsa44_sign" $
                    c_cardano_mldsa44_sign sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) skPtr

  verifyDSIGN () (VerKeyMLDSA44DSIGN vk) a (SigMLDSA44DSIGN sig) =
    let bs = getSignableRepresentation a
     in unsafeDupablePerformIO $
          BS.useAsCStringLen bs $ \(ptr, len) ->
            psbUseAsSizedPtr vk $ \vkPtr ->
              psbUseAsSizedPtr sig $ \sigPtr -> do
                rc <- c_cardano_mldsa44_verify sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) vkPtr
                return $
                  if rc == 0
                    then Right ()
                    else Left "Verification failed"

  --
  -- Key generation
  --
  genKeyDSIGN seed =
    SignKeyMLDSA44DSIGN $
      let (sb, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @MLDSA44DSIGN)) seed
       in unsafeDupablePerformIO $
            psbCreateSized $ \skPtr ->
              BS.useAsCStringLen sb $ \(seedPtr, _) ->
                mldsaOrThrow "genKeyDSIGN @MLDSA44DSIGN" "cardano_mldsa44_signkey_from_seed" $
                  c_cardano_mldsa44_signkey_from_seed skPtr (SizedPtr . castPtr $ seedPtr)

instance DSIGNMAlgorithm MLDSA44DSIGN where
  newtype SignKeyDSIGNM MLDSA44DSIGN
    = SignKeyMLDSA44DSIGNM (MLockedSizedBytes MLDSA44_SIGNKEYBYTES)
    deriving (Show)

  deriveVerKeyDSIGNM (SignKeyMLDSA44DSIGNM sk) =
    VerKeyMLDSA44DSIGN <$!> do
      mlsbUseAsSizedPtr sk $ \skPtr ->
        psbCreateSized $ \pkPtr ->
          unsafeIOToMonadST $ memcpySized pkPtr (signKeyPkPtr skPtr)

  signDSIGNM () a (SignKeyMLDSA44DSIGNM sk) =
    let bs = getSignableRepresentation a
     in do
          (psb, rc) <-
            mlsbUseAsSizedPtr sk $ \skPtr ->
              psbCreateSizedResult $ \sigPtr ->
                unsafeIOToMonadST $
                  BS.useAsCStringLen bs $ \(ptr, len) ->
                    c_cardano_mldsa44_sign sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) skPtr
          throwOnFailure "signDSIGNM @MLDSA44DSIGN" "cardano_mldsa44_sign" rc
          return $! SigMLDSA44DSIGN psb

  --
  -- Key generation
  --
  {-# NOINLINE genKeyDSIGNMWith #-}
  genKeyDSIGNMWith allocator seed = do
    sk <- mlsbNewWith allocator
    rc <-
      mlsbUseAsSizedPtr sk $ \skPtr ->
        mlockedSeedUseAsSizedPtr seed $ \seedPtr ->
          unsafeIOToMonadST $ c_cardano_mldsa44_signkey_from_seed skPtr seedPtr
    when (rc /= 0) $ mlsbFinalize sk
    throwOnFailure "genKeyDSIGNM @MLDSA44DSIGN" "cardano_mldsa44_signkey_from_seed" rc
    return $! SignKeyMLDSA44DSIGNM sk

  cloneKeyDSIGNMWith allocator (SignKeyMLDSA44DSIGNM sk) =
    SignKeyMLDSA44DSIGNM <$!> mlsbCopyWith allocator sk

  getSeedDSIGNMWith allocator _ (SignKeyMLDSA44DSIGNM sk) = do
    seed <- mlockedSeedNewWith allocator
    mlsbUseAsSizedPtr sk $ \skPtr ->
      mlockedSeedUseAsSizedPtr seed $ \seedPtr ->
        unsafeIOToMonadST $ memcpySized seedPtr (signKeySeedPtr skPtr)
    return seed

  --
  -- Secure forgetting
  --
  forgetSignKeyDSIGNMWith _ (SignKeyMLDSA44DSIGNM sk) = mlsbFinalize sk

instance UnsoundDSIGNMAlgorithm MLDSA44DSIGN where
  --
  -- Ser/deser (dangerous - do not use in production code)
  --
  rawSerialiseSignKeyDSIGNM sk = do
    seed <- getSeedDSIGNM (Proxy @MLDSA44DSIGN) sk
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

instance FixedSizeCodec (VerKeyDSIGN MLDSA44DSIGN) where
  type FixedSize (VerKeyDSIGN MLDSA44DSIGN) = MLDSA44_PUBLICKEYBYTES
  rawEncodeFixedSized (VerKeyMLDSA44DSIGN vk) = psbToByteString vk
  rawDecodeFixedSized bs = VerKeyMLDSA44DSIGN <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyDSIGN MLDSA44DSIGN) where
  -- \| Only the 32-octet seed is serialised (FIPS 204 Section 3.6.3 allows
  -- storing the seed as the private key). The expanded @sk || pk@ is
  -- recomputed on deserialisation.
  type FixedSize (SignKeyDSIGN MLDSA44DSIGN) = MLDSA44_SEEDBYTES
  rawEncodeFixedSized (SignKeyMLDSA44DSIGN sk) =
    BS.take (fromIntegral @Word @Int $ seedSizeDSIGN (Proxy @MLDSA44DSIGN)) $
      BS.drop mldsa44SignKeySeedOffset $
        psbToByteString sk
  rawDecodeFixedSized bs = guardFixedSized bs $ pure . genKeyDSIGN $ mkSeedFromBytes bs
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SigDSIGN MLDSA44DSIGN) where
  type FixedSize (SigDSIGN MLDSA44DSIGN) = MLDSA44_SIGBYTES
  rawEncodeFixedSized (SigMLDSA44DSIGN sig) = psbToByteString sig
  rawDecodeFixedSized bs = SigMLDSA44DSIGN <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance ToCBOR (VerKeyDSIGN MLDSA44DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN MLDSA44DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN MLDSA44DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN MLDSA44DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN MLDSA44DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN MLDSA44DSIGN) where
  fromCBOR = decodeFixedSized

instance
  TypeError ('Text "CBOR encoding would violate mlocking guarantees") =>
  ToCBOR (SignKeyDSIGNM MLDSA44DSIGN)
  where
  toCBOR = error "unsupported"
  encodedSizeExpr _ = error "unsupported"

instance
  TypeError ('Text "CBOR decoding would violate mlocking guarantees") =>
  FromCBOR (SignKeyDSIGNM MLDSA44DSIGN)
  where
  fromCBOR = error "unsupported"

instance DirectSerialise (SignKeyDSIGNM MLDSA44DSIGN) where
  -- /Note:/ Only the 32-octet seed is serialised; @sk || pk@ is regenerated
  -- from it on deserialisation.
  directSerialise push sk = do
    bracket
      (getSeedDSIGNM (Proxy @MLDSA44DSIGN) sk)
      mlockedSeedFinalize
      ( \seed -> mlockedSeedUseAsCPtr seed $ \ptr ->
          push
            (castPtr ptr)
            (fromIntegral @Word @CSize $ seedSizeDSIGN (Proxy @MLDSA44DSIGN))
      )

instance DirectDeserialise (SignKeyDSIGNM MLDSA44DSIGN) where
  directDeserialise pull = do
    bracket
      mlockedSeedNew
      mlockedSeedFinalize
      ( \seed -> do
          mlockedSeedUseAsCPtr seed $ \ptr -> do
            pull
              (castPtr ptr)
              (fromIntegral @Word @CSize $ seedSizeDSIGN (Proxy @MLDSA44DSIGN))
          genKeyDSIGNM seed
      )

instance DirectSerialise (VerKeyDSIGN MLDSA44DSIGN) where
  directSerialise push (VerKeyMLDSA44DSIGN psb) = do
    psbUseAsCPtrLen psb $ \ptr _ ->
      push
        (castPtr ptr)
        (fromIntegral @Word @CSize $ fixedSize (Proxy @(VerKeyDSIGN MLDSA44DSIGN)))

instance DirectDeserialise (VerKeyDSIGN MLDSA44DSIGN) where
  directDeserialise pull = do
    psb <- psbCreate $ \ptr ->
      pull
        (castPtr ptr)
        (fromIntegral @Word @CSize $ fixedSize (Proxy @(VerKeyDSIGN MLDSA44DSIGN)))
    return $! VerKeyMLDSA44DSIGN psb
