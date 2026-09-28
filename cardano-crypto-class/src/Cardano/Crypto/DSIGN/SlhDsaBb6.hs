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

-- | SLH-DSA (FIPS 205 mechanisms) with the reduced-budget parameter set
-- \"bb-6\" of Fluhrer and Dang (2024, Appendix C): n = 16, one tree of
-- height 9, FORS 11 x 2^14, w = 16, SHA2-simple. Sized for a signer that
-- issues at most 2^10 signatures per key, which is what one KES period
-- needs; the set is published but not standardised. Over the vendored
-- SPHINCS+ reference sources in @cbits/sphincsplus-ref@.
--
-- Signing is the deterministic variant (@opt_rand = PK.seed@). The 32-octet
-- seed is expanded to the scheme's 48-octet seed with SHA-256.
--
-- The in-memory sign key is @seed || sk || pk@ (32 + 64 + 32 octets), so
-- that 'deriveVerKeyDSIGN' and 'getSeedDSIGNM' are plain copies. Only the
-- 32-octet seed is serialised; the key is regenerated on deserialisation,
-- which costs a key generation (the whole 2^9-leaf tree, tens of ms).
module Cardano.Crypto.DSIGN.SlhDsaBb6 (
  SlhDsaBb6DSIGN,
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
import Cardano.Crypto.SLHDSA.C
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (SignableRepresentation (..))
import Cardano.Foreign

data SlhDsaBb6DSIGN

instance NoThunks (VerKeyDSIGN SlhDsaBb6DSIGN)
instance NoThunks (SignKeyDSIGN SlhDsaBb6DSIGN)
instance NoThunks (SigDSIGN SlhDsaBb6DSIGN)

deriving via
  (MLockedSizedBytes SLHDSA_BB6_SIGNKEYBYTES)
  instance
    NoThunks (SignKeyDSIGNM SlhDsaBb6DSIGN)

instance NFData (SignKeyDSIGNM SlhDsaBb6DSIGN) where
  rnf = rwhnf

--
-- Sign key layout helpers
--

-- | The seed slot of an in-memory sign key.
signKeySeedPtr :: SizedPtr SLHDSA_BB6_SIGNKEYBYTES -> SizedPtr SLHDSA_BB6_SEEDBYTES
signKeySeedPtr (SizedPtr p) = SizedPtr (p `plusPtr` slhdsaBb6SignKeySeedOffset)

-- | The public key slot of an in-memory sign key.
signKeyPkPtr :: SizedPtr SLHDSA_BB6_SIGNKEYBYTES -> SizedPtr SLHDSA_BB6_PUBLICKEYBYTES
signKeyPkPtr (SizedPtr p) = SizedPtr (p `plusPtr` slhdsaBb6SignKeyPkOffset)

--
-- Error reporting. The SPHINCS+ reference reports failures through its return code,
-- not errno.
--

slhdsaError :: String -> String -> CInt -> IOError
slhdsaError contextDesc cFunName rc =
  userError (contextDesc ++ ": " ++ cFunName ++ " failed with code " ++ show rc)

-- | Run an FFI call returning a status code and throw on a non-zero result.
slhdsaOrThrow :: String -> String -> IO CInt -> IO ()
slhdsaOrThrow contextDesc cFunName action = do
  rc <- action
  unless (rc == 0) $ ioError (slhdsaError contextDesc cFunName rc)

-- | Throw on a non-zero status code, outside of ST.
throwOnFailure :: MonadThrow m => String -> String -> CInt -> m ()
throwOnFailure contextDesc cFunName rc =
  unless (rc == 0) $ throwIO (slhdsaError contextDesc cFunName rc)

instance DSIGNAlgorithm SlhDsaBb6DSIGN where
  type SeedSizeDSIGN SlhDsaBb6DSIGN = SLHDSA_BB6_SEEDBYTES

  --
  -- Key and signature types
  --

  newtype VerKeyDSIGN SlhDsaBb6DSIGN
    = VerKeySlhDsaBb6DSIGN (PinnedSizedBytes SLHDSA_BB6_PUBLICKEYBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  -- The in-memory representation is @seed || sk || pk@; the declared
  -- (serialised) sign key size is the seed size, see 'FixedSizeCodec' below.
  newtype SignKeyDSIGN SlhDsaBb6DSIGN
    = SignKeySlhDsaBb6DSIGN (PinnedSizedBytes SLHDSA_BB6_SIGNKEYBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  newtype SigDSIGN SlhDsaBb6DSIGN
    = SigSlhDsaBb6DSIGN (PinnedSizedBytes SLHDSA_BB6_SIGBYTES)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGN _ = "slhdsa_bb6"

  deriveVerKeyDSIGN (SignKeySlhDsaBb6DSIGN sk) =
    VerKeySlhDsaBb6DSIGN $
      unsafeDupablePerformIO $
        psbUseAsSizedPtr sk $ \skPtr ->
          psbCreateSized $ \pkPtr ->
            memcpySized pkPtr (signKeyPkPtr skPtr)

  --
  -- Core algorithm operations
  --

  type Signable SlhDsaBb6DSIGN = SignableRepresentation

  signDSIGN () a (SignKeySlhDsaBb6DSIGN sk) =
    let bs = getSignableRepresentation a
     in SigSlhDsaBb6DSIGN $
          unsafeDupablePerformIO $
            BS.useAsCStringLen bs $ \(ptr, len) ->
              psbUseAsSizedPtr sk $ \skPtr ->
                psbCreateSized $ \sigPtr ->
                  slhdsaOrThrow "signDSIGN @SlhDsaBb6DSIGN" "cardano_slhdsa_bb6_sign" $
                    c_cardano_slhdsa_bb6_sign sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) skPtr

  verifyDSIGN () (VerKeySlhDsaBb6DSIGN vk) a (SigSlhDsaBb6DSIGN sig) =
    let bs = getSignableRepresentation a
     in unsafeDupablePerformIO $
          BS.useAsCStringLen bs $ \(ptr, len) ->
            psbUseAsSizedPtr vk $ \vkPtr ->
              psbUseAsSizedPtr sig $ \sigPtr -> do
                rc <- c_cardano_slhdsa_bb6_verify sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) vkPtr
                return $
                  if rc == 0
                    then Right ()
                    else Left "Verification failed"

  --
  -- Key generation
  --
  genKeyDSIGN seed =
    SignKeySlhDsaBb6DSIGN $
      let (sb, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @SlhDsaBb6DSIGN)) seed
       in unsafeDupablePerformIO $
            psbCreateSized $ \skPtr ->
              BS.useAsCStringLen sb $ \(seedPtr, _) ->
                slhdsaOrThrow "genKeyDSIGN @SlhDsaBb6DSIGN" "cardano_slhdsa_bb6_signkey_from_seed" $
                  c_cardano_slhdsa_bb6_signkey_from_seed skPtr (SizedPtr . castPtr $ seedPtr)

instance DSIGNMAlgorithm SlhDsaBb6DSIGN where
  newtype SignKeyDSIGNM SlhDsaBb6DSIGN
    = SignKeySlhDsaBb6DSIGNM (MLockedSizedBytes SLHDSA_BB6_SIGNKEYBYTES)
    deriving (Show)

  deriveVerKeyDSIGNM (SignKeySlhDsaBb6DSIGNM sk) =
    VerKeySlhDsaBb6DSIGN <$!> do
      mlsbUseAsSizedPtr sk $ \skPtr ->
        psbCreateSized $ \pkPtr ->
          unsafeIOToMonadST $ memcpySized pkPtr (signKeyPkPtr skPtr)

  signDSIGNM () a (SignKeySlhDsaBb6DSIGNM sk) =
    let bs = getSignableRepresentation a
     in do
          (psb, rc) <-
            mlsbUseAsSizedPtr sk $ \skPtr ->
              psbCreateSizedResult $ \sigPtr ->
                unsafeIOToMonadST $
                  BS.useAsCStringLen bs $ \(ptr, len) ->
                    c_cardano_slhdsa_bb6_sign sigPtr (castPtr ptr) (fromIntegral @Int @CSize len) skPtr
          throwOnFailure "signDSIGNM @SlhDsaBb6DSIGN" "cardano_slhdsa_bb6_sign" rc
          return $! SigSlhDsaBb6DSIGN psb

  --
  -- Key generation
  --
  {-# NOINLINE genKeyDSIGNMWith #-}
  genKeyDSIGNMWith allocator seed = do
    sk <- mlsbNewWith allocator
    rc <-
      mlsbUseAsSizedPtr sk $ \skPtr ->
        mlockedSeedUseAsSizedPtr seed $ \seedPtr ->
          unsafeIOToMonadST $ c_cardano_slhdsa_bb6_signkey_from_seed skPtr seedPtr
    when (rc /= 0) $ mlsbFinalize sk
    throwOnFailure "genKeyDSIGNM @SlhDsaBb6DSIGN" "cardano_slhdsa_bb6_signkey_from_seed" rc
    return $! SignKeySlhDsaBb6DSIGNM sk

  cloneKeyDSIGNMWith allocator (SignKeySlhDsaBb6DSIGNM sk) =
    SignKeySlhDsaBb6DSIGNM <$!> mlsbCopyWith allocator sk

  getSeedDSIGNMWith allocator _ (SignKeySlhDsaBb6DSIGNM sk) = do
    seed <- mlockedSeedNewWith allocator
    mlsbUseAsSizedPtr sk $ \skPtr ->
      mlockedSeedUseAsSizedPtr seed $ \seedPtr ->
        unsafeIOToMonadST $ memcpySized seedPtr (signKeySeedPtr skPtr)
    return seed

  --
  -- Secure forgetting
  --
  forgetSignKeyDSIGNMWith _ (SignKeySlhDsaBb6DSIGNM sk) = mlsbFinalize sk

instance UnsoundDSIGNMAlgorithm SlhDsaBb6DSIGN where
  --
  -- Ser/deser (dangerous - do not use in production code)
  --
  rawSerialiseSignKeyDSIGNM sk = do
    seed <- getSeedDSIGNM (Proxy @SlhDsaBb6DSIGN) sk
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

instance FixedSizeCodec (VerKeyDSIGN SlhDsaBb6DSIGN) where
  type FixedSize (VerKeyDSIGN SlhDsaBb6DSIGN) = SLHDSA_BB6_PUBLICKEYBYTES
  rawEncodeFixedSized (VerKeySlhDsaBb6DSIGN vk) = psbToByteString vk
  rawDecodeFixedSized bs = VerKeySlhDsaBb6DSIGN <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyDSIGN SlhDsaBb6DSIGN) where
  -- \| Only the 32-octet seed is serialised. The expanded @sk || pk@ is
  -- recomputed on deserialisation (a full key generation).
  type FixedSize (SignKeyDSIGN SlhDsaBb6DSIGN) = SLHDSA_BB6_SEEDBYTES
  rawEncodeFixedSized (SignKeySlhDsaBb6DSIGN sk) =
    BS.take (fromIntegral @Word @Int $ seedSizeDSIGN (Proxy @SlhDsaBb6DSIGN)) $
      BS.drop slhdsaBb6SignKeySeedOffset $
        psbToByteString sk
  rawDecodeFixedSized bs = guardFixedSized bs $ pure . genKeyDSIGN $ mkSeedFromBytes bs
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SigDSIGN SlhDsaBb6DSIGN) where
  type FixedSize (SigDSIGN SlhDsaBb6DSIGN) = SLHDSA_BB6_SIGBYTES
  rawEncodeFixedSized (SigSlhDsaBb6DSIGN sig) = psbToByteString sig
  rawDecodeFixedSized bs = SigSlhDsaBb6DSIGN <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance ToCBOR (VerKeyDSIGN SlhDsaBb6DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN SlhDsaBb6DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN SlhDsaBb6DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN SlhDsaBb6DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN SlhDsaBb6DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN SlhDsaBb6DSIGN) where
  fromCBOR = decodeFixedSized

instance
  TypeError ('Text "CBOR encoding would violate mlocking guarantees") =>
  ToCBOR (SignKeyDSIGNM SlhDsaBb6DSIGN)
  where
  toCBOR = error "unsupported"
  encodedSizeExpr _ = error "unsupported"

instance
  TypeError ('Text "CBOR decoding would violate mlocking guarantees") =>
  FromCBOR (SignKeyDSIGNM SlhDsaBb6DSIGN)
  where
  fromCBOR = error "unsupported"

instance DirectSerialise (SignKeyDSIGNM SlhDsaBb6DSIGN) where
  -- /Note:/ Only the 32-octet seed is serialised; @sk || pk@ is regenerated
  -- from it on deserialisation.
  directSerialise push sk = do
    bracket
      (getSeedDSIGNM (Proxy @SlhDsaBb6DSIGN) sk)
      mlockedSeedFinalize
      ( \seed -> mlockedSeedUseAsCPtr seed $ \ptr ->
          push
            (castPtr ptr)
            (fromIntegral @Word @CSize $ seedSizeDSIGN (Proxy @SlhDsaBb6DSIGN))
      )

instance DirectDeserialise (SignKeyDSIGNM SlhDsaBb6DSIGN) where
  directDeserialise pull = do
    bracket
      mlockedSeedNew
      mlockedSeedFinalize
      ( \seed -> do
          mlockedSeedUseAsCPtr seed $ \ptr -> do
            pull
              (castPtr ptr)
              (fromIntegral @Word @CSize $ seedSizeDSIGN (Proxy @SlhDsaBb6DSIGN))
          genKeyDSIGNM seed
      )

instance DirectSerialise (VerKeyDSIGN SlhDsaBb6DSIGN) where
  directSerialise push (VerKeySlhDsaBb6DSIGN psb) = do
    psbUseAsCPtrLen psb $ \ptr _ ->
      push
        (castPtr ptr)
        (fromIntegral @Word @CSize $ fixedSize (Proxy @(VerKeyDSIGN SlhDsaBb6DSIGN)))

instance DirectDeserialise (VerKeyDSIGN SlhDsaBb6DSIGN) where
  directDeserialise pull = do
    psb <- psbCreate $ \ptr ->
      pull
        (castPtr ptr)
        (fromIntegral @Word @CSize $ fixedSize (Proxy @(VerKeyDSIGN SlhDsaBb6DSIGN)))
    return $! VerKeySlhDsaBb6DSIGN psb
