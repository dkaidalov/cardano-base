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

-- | Falcon-512 digital signatures, over the vendored PQClean
-- @falcon-padded-512@ sources in @cbits/falcon-padded-512@.
--
-- Key generation is derived from a 32-octet seed. Signing is deterministic:
-- the nonce and the Gaussian sampler seed are derived from the private key
-- and the message (Falcon as specified draws both at random; this keeps the
-- pure 'signDSIGN' honest and does not change the cost). Signatures use the
-- padded, fixed-length 666-octet encoding.
--
-- The in-memory sign key is @seed || sk || pk@ (32 + 1281 + 897 octets), so
-- that 'deriveVerKeyDSIGN' and 'getSeedDSIGNM' are plain copies. Only the
-- 32-octet seed is serialised; the expanded key is regenerated on
-- deserialisation, which for Falcon costs a full key generation (about
-- 10 ms).
module Cardano.Crypto.DSIGN.Falcon512 (
  Falcon512DSIGN,
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
import Cardano.Crypto.Falcon.C
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
import Cardano.Foreign

data Falcon512DSIGN

instance NoThunks (VerKeyDSIGN Falcon512DSIGN)
instance NoThunks (SignKeyDSIGN Falcon512DSIGN)
instance NoThunks (SigDSIGN Falcon512DSIGN)

deriving via
  (MLockedSizedBytes FALCON512_SIGNKEYBYTES)
  instance
    NoThunks (SignKeyDSIGNM Falcon512DSIGN)

instance NFData (SignKeyDSIGNM Falcon512DSIGN) where
  rnf = rwhnf

--
-- Sign key layout helpers
--

-- | The seed slot of an in-memory sign key.
signKeySeedPtr :: SizedPtr FALCON512_SIGNKEYBYTES -> SizedPtr FALCON512_SEEDBYTES
signKeySeedPtr (SizedPtr p) = SizedPtr (p `plusPtr` falcon512SignKeySeedOffset)

-- | The public key slot of an in-memory sign key.
signKeyPkPtr :: SizedPtr FALCON512_SIGNKEYBYTES -> SizedPtr FALCON512_PUBLICKEYBYTES
signKeyPkPtr (SizedPtr p) = SizedPtr (p `plusPtr` falcon512SignKeyPkOffset)

--
-- Error reporting. PQClean reports failures through its return code,
-- not errno.
--

falconError :: String -> String -> CInt -> IOError
falconError contextDesc cFunName rc =
  userError (contextDesc ++ ": " ++ cFunName ++ " failed with code " ++ show rc)

-- | Run an FFI call returning a status code and throw on a non-zero result.
falconOrThrow :: String -> String -> IO CInt -> IO ()
falconOrThrow contextDesc cFunName action = do
  rc <- action
  unless (rc == 0) $ ioError (falconError contextDesc cFunName rc)

-- | Throw on a non-zero status code, outside of ST.
throwOnFailure :: MonadThrow m => String -> String -> CInt -> m ()
throwOnFailure contextDesc cFunName rc =
  unless (rc == 0) $ throwIO (falconError contextDesc cFunName rc)

instance DSIGNAlgorithm Falcon512DSIGN where
  type SeedSizeDSIGN Falcon512DSIGN = FALCON512_SEEDBYTES

  --
  -- Key and signature types
  --

  newtype VerKeyDSIGN Falcon512DSIGN
    = VerKeyFalcon512DSIGN (PinnedSizedBytes FALCON512_PUBLICKEYBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  -- The in-memory representation is @seed || sk || pk@; the declared
  -- (serialised) sign key size is the seed size, see 'FixedSizeCodec' below.
  newtype SignKeyDSIGN Falcon512DSIGN
    = SignKeyFalcon512DSIGN (PinnedSizedBytes FALCON512_SIGNKEYBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  newtype SigDSIGN Falcon512DSIGN
    = SigFalcon512DSIGN (PinnedSizedBytes FALCON512_SIGBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGN _ = "falcon512"

  deriveVerKeyDSIGN (SignKeyFalcon512DSIGN sk) =
    VerKeyFalcon512DSIGN $
      unsafeDupablePerformIO $
        psbUseAsSizedPtr sk $ \skPtr ->
          psbCreateSized $ \pkPtr ->
            memcpySized pkPtr (signKeyPkPtr skPtr)

  --
  -- Core algorithm operations
  --

  type Signable Falcon512DSIGN = SignableRepresentation

  signDSIGN () a (SignKeyFalcon512DSIGN sk) =
    let bs = getSignableRepresentation a
     in SigFalcon512DSIGN $
          unsafeDupablePerformIO $
            BS.useAsCStringLen bs $ \(ptr, len) ->
              psbUseAsSizedPtr sk $ \skPtr ->
                psbCreateSized $ \sigPtr ->
                  falconOrThrow "signDSIGN @Falcon512DSIGN" "cardano_falcon512_sign" $
                    c_cardano_falcon512_sign sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) skPtr

  verifyDSIGN () (VerKeyFalcon512DSIGN vk) a (SigFalcon512DSIGN sig) =
    let bs = getSignableRepresentation a
     in unsafeDupablePerformIO $
          BS.useAsCStringLen bs $ \(ptr, len) ->
            psbUseAsSizedPtr vk $ \vkPtr ->
              psbUseAsSizedPtr sig $ \sigPtr -> do
                rc <- c_cardano_falcon512_verify sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) vkPtr
                return $
                  if rc == 0
                    then Right ()
                    else Left "Verification failed"

  --
  -- Key generation
  --
  genKeyDSIGN seed =
    SignKeyFalcon512DSIGN $
      let (sb, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @Falcon512DSIGN)) seed
       in unsafeDupablePerformIO $
            psbCreateSized $ \skPtr ->
              BS.useAsCStringLen sb $ \(seedPtr, _) ->
                falconOrThrow "genKeyDSIGN @Falcon512DSIGN" "cardano_falcon512_signkey_from_seed" $
                  c_cardano_falcon512_signkey_from_seed skPtr (SizedPtr . castPtr $ seedPtr)

instance DSIGNMAlgorithm Falcon512DSIGN where
  newtype SignKeyDSIGNM Falcon512DSIGN
    = SignKeyFalcon512DSIGNM (MLockedSizedBytes FALCON512_SIGNKEYBYTES)
    deriving (Show)

  deriveVerKeyDSIGNM (SignKeyFalcon512DSIGNM sk) =
    VerKeyFalcon512DSIGN <$!> do
      mlsbUseAsSizedPtr sk $ \skPtr ->
        psbCreateSized $ \pkPtr ->
          unsafeIOToMonadST $ memcpySized pkPtr (signKeyPkPtr skPtr)

  signDSIGNM () a (SignKeyFalcon512DSIGNM sk) =
    let bs = getSignableRepresentation a
     in do
          (psb, rc) <-
            mlsbUseAsSizedPtr sk $ \skPtr ->
              psbCreateSizedResult $ \sigPtr ->
                unsafeIOToMonadST $
                  BS.useAsCStringLen bs $ \(ptr, len) ->
                    c_cardano_falcon512_sign sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) skPtr
          throwOnFailure "signDSIGNM @Falcon512DSIGN" "cardano_falcon512_sign" rc
          return $! SigFalcon512DSIGN psb

  --
  -- Key generation
  --
  {-# NOINLINE genKeyDSIGNMWith #-}
  genKeyDSIGNMWith allocator seed = do
    sk <- mlsbNewWith allocator
    rc <-
      mlsbUseAsSizedPtr sk $ \skPtr ->
        mlockedSeedUseAsSizedPtr seed $ \seedPtr ->
          unsafeIOToMonadST $ c_cardano_falcon512_signkey_from_seed skPtr seedPtr
    when (rc /= 0) $ mlsbFinalize sk
    throwOnFailure "genKeyDSIGNM @Falcon512DSIGN" "cardano_falcon512_signkey_from_seed" rc
    return $! SignKeyFalcon512DSIGNM sk

  cloneKeyDSIGNMWith allocator (SignKeyFalcon512DSIGNM sk) =
    SignKeyFalcon512DSIGNM <$!> mlsbCopyWith allocator sk

  getSeedDSIGNMWith allocator _ (SignKeyFalcon512DSIGNM sk) = do
    seed <- mlockedSeedNewWith allocator
    mlsbUseAsSizedPtr sk $ \skPtr ->
      mlockedSeedUseAsSizedPtr seed $ \seedPtr ->
        unsafeIOToMonadST $ memcpySized seedPtr (signKeySeedPtr skPtr)
    return seed

  --
  -- Secure forgetting
  --
  forgetSignKeyDSIGNMWith _ (SignKeyFalcon512DSIGNM sk) = mlsbFinalize sk

instance UnsoundDSIGNMAlgorithm Falcon512DSIGN where
  --
  -- Ser/deser (dangerous - do not use in production code)
  --
  rawSerialiseSignKeyDSIGNM sk = do
    seed <- getSeedDSIGNM (Proxy @Falcon512DSIGN) sk
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

instance FixedSizeCodec (VerKeyDSIGN Falcon512DSIGN) where
  type FixedSize (VerKeyDSIGN Falcon512DSIGN) = FALCON512_PUBLICKEYBYTES
  rawEncodeFixedSized (VerKeyFalcon512DSIGN vk) = psbToByteString vk
  rawDecodeFixedSized bs = VerKeyFalcon512DSIGN <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyDSIGN Falcon512DSIGN) where
  -- \| Only the 32-octet seed is serialised. The expanded @sk || pk@ is
  -- recomputed on deserialisation (a full Falcon key generation).
  type FixedSize (SignKeyDSIGN Falcon512DSIGN) = FALCON512_SEEDBYTES
  rawEncodeFixedSized (SignKeyFalcon512DSIGN sk) =
    BS.take (fromIntegral @Word @Int $ seedSizeDSIGN (Proxy @Falcon512DSIGN)) $
      BS.drop falcon512SignKeySeedOffset $
        psbToByteString sk
  rawDecodeFixedSized bs = guardFixedSized bs $ pure . genKeyDSIGN $ mkSeedFromBytes bs
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SigDSIGN Falcon512DSIGN) where
  type FixedSize (SigDSIGN Falcon512DSIGN) = FALCON512_SIGBYTES
  rawEncodeFixedSized (SigFalcon512DSIGN sig) = psbToByteString sig
  rawDecodeFixedSized bs = SigFalcon512DSIGN <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance ToCBOR (VerKeyDSIGN Falcon512DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN Falcon512DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN Falcon512DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN Falcon512DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN Falcon512DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN Falcon512DSIGN) where
  fromCBOR = decodeFixedSized

instance
  TypeError ('Text "CBOR encoding would violate mlocking guarantees") =>
  ToCBOR (SignKeyDSIGNM Falcon512DSIGN)
  where
  toCBOR = error "unsupported"
  encodedSizeExpr _ = error "unsupported"

instance
  TypeError ('Text "CBOR decoding would violate mlocking guarantees") =>
  FromCBOR (SignKeyDSIGNM Falcon512DSIGN)
  where
  fromCBOR = error "unsupported"

instance DirectSerialise (SignKeyDSIGNM Falcon512DSIGN) where
  -- /Note:/ Only the 32-octet seed is serialised; @sk || pk@ is regenerated
  -- from it on deserialisation.
  directSerialise push sk = do
    bracket
      (getSeedDSIGNM (Proxy @Falcon512DSIGN) sk)
      mlockedSeedFinalize
      ( \seed -> mlockedSeedUseAsCPtr seed $ \ptr ->
          push
            (castPtr ptr)
            (fromIntegral @Word @CSize $ seedSizeDSIGN (Proxy @Falcon512DSIGN))
      )

instance DirectDeserialise (SignKeyDSIGNM Falcon512DSIGN) where
  directDeserialise pull = do
    bracket
      mlockedSeedNew
      mlockedSeedFinalize
      ( \seed -> do
          mlockedSeedUseAsCPtr seed $ \ptr -> do
            pull
              (castPtr ptr)
              (fromIntegral @Word @CSize $ seedSizeDSIGN (Proxy @Falcon512DSIGN))
          genKeyDSIGNM seed
      )

instance DirectSerialise (VerKeyDSIGN Falcon512DSIGN) where
  directSerialise push (VerKeyFalcon512DSIGN psb) = do
    psbUseAsCPtrLen psb $ \ptr _ ->
      push
        (castPtr ptr)
        (fromIntegral @Word @CSize $ fixedSize (Proxy @(VerKeyDSIGN Falcon512DSIGN)))

instance DirectDeserialise (VerKeyDSIGN Falcon512DSIGN) where
  directDeserialise pull = do
    psb <- psbCreate $ \ptr ->
      pull
        (castPtr ptr)
        (fromIntegral @Word @CSize $ fixedSize (Proxy @(VerKeyDSIGN Falcon512DSIGN)))
    return $! VerKeyFalcon512DSIGN psb
