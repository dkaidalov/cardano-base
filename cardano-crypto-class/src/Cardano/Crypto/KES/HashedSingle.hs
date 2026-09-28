{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NoStarIsType #-}

-- | A single-period KES whose verification key is the hash of the underlying
-- 'DSIGNMAlgorithm' verification key.
--
-- Like "Cardano.Crypto.KES.CompactSingle", the signature carries the DSIGN
-- verification key so that the sum composition in
-- "Cardano.Crypto.KES.CompactSum" can rebuild the Merkle path from the
-- signature alone. Unlike 'CompactSingleKES', the KES verification key is not
-- the DSIGN key itself but its @h@-hash, a 32-byte commitment for
-- 'Cardano.Crypto.Hash.Blake2b.Blake2b_256'.
--
-- For a DSIGN scheme with a small verification key this changes nothing of
-- note. For a scheme with a large one, such as ML-DSA-44 (1312 bytes), it
-- shrinks a compact sum signature considerably: 'CompactSumKES' stores the
-- sibling's 'VerKeyKES' at every level, and at the innermost level that
-- sibling is a leaf. With 'CompactSingleKES' as the leaf, the innermost
-- sibling key is a full DSIGN key; with 'HashedSingleKES' it is a hash, and
-- the only full DSIGN key in the signature is the signer's own, inside the
-- leaf signature. The saving is @|vk| - |hash|@ bytes per signature, so the
-- wrapper pays off exactly when the DSIGN key is larger than the hash.
--
-- Verification checks the commitment before the signature: the key embedded
-- in the signature must hash to the expected verification key, so forging
-- under a substituted key requires a second preimage of @h@.
--
-- 'HashedCompactSum6KES' and friends are the compact sums over this leaf.
module Cardano.Crypto.KES.HashedSingle (
  HashedSingleKES,
  VerKeyKES (..),
  SignKeyKES (..),
  SigKES (..),

  -- * Type aliases for compact sums over a hashed leaf
  HashedCompactSum0KES,
  HashedCompactSum1KES,
  HashedCompactSum2KES,
  HashedCompactSum3KES,
  HashedCompactSum4KES,
  HashedCompactSum5KES,
  HashedCompactSum6KES,
  HashedCompactSum7KES,
) where

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  guardFixedSized,
 )
import Control.Monad ((<$!>))
import qualified Data.ByteString.Internal as BS
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable)
import Foreign.C.Types (CSize)
import Foreign.Ptr (castPtr)
import GHC.Generics (Generic)
import GHC.TypeLits (KnownNat, type (+))
import NoThunks.Class (NoThunks)

import Control.DeepSeq (NFData)
import Control.Exception (assert)

import Cardano.Base.Bytes (slice)
import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.DSIGN.Class as DSIGN
import Cardano.Crypto.DirectSerialise
import Cardano.Crypto.Hash.Class
import Cardano.Crypto.KES.Class
import Cardano.Crypto.KES.CompactSum (CompactSumKES)
import Cardano.Crypto.Libsodium.Memory (
  mallocForeignPtrBytes,
  unpackByteStringCStringLen,
  unsafeRawForeignPtr,
  withForeignPtr,
 )

-- | A 2^0 period KES with a hashed verification key
type HashedCompactSum0KES d h = HashedSingleKES h d

-- | A 2^1 period KES
type HashedCompactSum1KES d h = CompactSumKES h (HashedCompactSum0KES d h)

-- | A 2^2 period KES
type HashedCompactSum2KES d h = CompactSumKES h (HashedCompactSum1KES d h)

-- | A 2^3 period KES
type HashedCompactSum3KES d h = CompactSumKES h (HashedCompactSum2KES d h)

-- | A 2^4 period KES
type HashedCompactSum4KES d h = CompactSumKES h (HashedCompactSum3KES d h)

-- | A 2^5 period KES
type HashedCompactSum5KES d h = CompactSumKES h (HashedCompactSum4KES d h)

-- | A 2^6 period KES
type HashedCompactSum6KES d h = CompactSumKES h (HashedCompactSum5KES d h)

-- | A 2^7 period KES
type HashedCompactSum7KES d h = CompactSumKES h (HashedCompactSum6KES d h)

-- | A single-period KES over @d@ whose verification key is the @h@-hash of
-- the DSIGN verification key.
data HashedSingleKES h d

deriving newtype instance NFData (VerKeyKES (HashedSingleKES h d))
deriving newtype instance NFData (SignKeyDSIGNM d) => NFData (SignKeyKES (HashedSingleKES h d))

deriving instance
  (NFData (SigDSIGN d), NFData (VerKeyDSIGN d)) => NFData (SigKES (HashedSingleKES h d))

instance
  ( DSIGNMAlgorithm d
  , HashAlgorithm h
  , KnownNat (SigSizeDSIGN d + VerKeySizeDSIGN d)
  ) =>
  KESAlgorithm (HashedSingleKES h d)
  where
  type SeedSizeKES (HashedSingleKES h d) = SeedSizeDSIGN d

  --
  -- Key and signature types
  --

  newtype VerKeyKES (HashedSingleKES h d) = VerKeyHashedSingleKES (Hash h (VerKeyDSIGN d))
    deriving (Generic)

  data SigKES (HashedSingleKES h d) = SigHashedSingleKES !(SigDSIGN d) !(VerKeyDSIGN d)
    deriving (Generic)

  newtype SignKeyKES (HashedSingleKES h d) = SignKeyHashedSingleKES (SignKeyDSIGNM d)

  type ContextKES (HashedSingleKES h d) = ContextDSIGN d
  type Signable (HashedSingleKES h d) = DSIGN.Signable d

  --
  -- Metadata and basic key operations
  --

  algorithmNameKES _ = algorithmNameDSIGN (Proxy :: Proxy d) ++ "_hashed_kes_2^0"

  type TotalPeriodsKES (HashedSingleKES h d) = 1

  --
  -- Core algorithm operations
  --

  verifyKES = verifyOptimizedKES

  --
  -- raw serialise/deserialise
  --

  type SignKeySizeKES (HashedSingleKES h d) = SignKeySizeDSIGN d

  -- The verification key is already a hash; see the note on 'hashVerKeyKES'
  -- in "Cardano.Crypto.KES.CompactSum" for why it is hashed again here.
  hashVerKeyKES (VerKeyHashedSingleKES vk) = castHash (hashWith hashToBytes vk)

  deriveVerKeyKES (SignKeyHashedSingleKES v) =
    VerKeyHashedSingleKES . hashVerKeyDSIGN <$!> deriveVerKeyDSIGNM v

  --
  -- Core algorithm operations
  --
  signKES ctxt t a (SignKeyHashedSingleKES sk) =
    assert (t == 0) $
      SigHashedSingleKES <$!> signDSIGNM ctxt a sk <*> deriveVerKeyDSIGNM sk

  updateKESWith _allocator _ctx (SignKeyHashedSingleKES _sk) _to = return Nothing

  --
  -- Key generation
  --

  genKeyKESWith allocator seed = SignKeyHashedSingleKES <$!> genKeyDSIGNMWith allocator seed

  --
  -- forgetting
  --
  forgetSignKeyKESWith allocator (SignKeyHashedSingleKES v) =
    forgetSignKeyDSIGNMWith allocator v

instance
  ( KESAlgorithm (HashedSingleKES h d)
  , UnsoundDSIGNMAlgorithm d
  , HashAlgorithm h
  ) =>
  UnsoundPureKESAlgorithm (HashedSingleKES h d)
  where
  data UnsoundPureSignKeyKES (HashedSingleKES h d)
    = UnsoundPureSignKeyHashedSingleKES (SignKeyDSIGN d)
    deriving (Generic)

  unsoundPureSignKES ctxt t a (UnsoundPureSignKeyHashedSingleKES sk) =
    assert (t == 0) $!
      SigHashedSingleKES (signDSIGN ctxt a sk) (deriveVerKeyDSIGN sk)

  unsoundPureUpdateKES _ctx _sk _to = Nothing

  --
  -- Key generation
  --

  unsoundPureGenKeyKES seed =
    UnsoundPureSignKeyHashedSingleKES $! genKeyDSIGN seed

  unsoundPureDeriveVerKeyKES (UnsoundPureSignKeyHashedSingleKES v) =
    VerKeyHashedSingleKES $! hashVerKeyDSIGN (deriveVerKeyDSIGN v)

  unsoundPureSignKeyKESToSoundSignKeyKES =
    unsoundPureSignKeyKESToSoundSignKeyKESViaSer

instance
  ( KESAlgorithm (HashedSingleKES h d)
  , DSIGNMAlgorithm d
  , HashAlgorithm h
  ) =>
  OptimizedKESAlgorithm (HashedSingleKES h d)
  where
  verifySigKES ctxt t a (SigHashedSingleKES sig vk) =
    assert (t == 0) $
      verifyDSIGN ctxt vk a sig

  -- 'verifyOptimizedKES' compares this against the caller's verification
  -- key, which is what binds the embedded DSIGN key to the commitment.
  verKeyFromSigKES _ctxt t (SigHashedSingleKES _ vk) =
    assert (t == 0) $
      VerKeyHashedSingleKES (hashVerKeyDSIGN vk)

instance
  (KESAlgorithm (HashedSingleKES h d), UnsoundDSIGNMAlgorithm d) =>
  UnsoundKESAlgorithm (HashedSingleKES h d)
  where
  rawSerialiseSignKeyKES (SignKeyHashedSingleKES sk) = rawSerialiseSignKeyDSIGNM sk
  rawDeserialiseSignKeyKESWith allocator bs = fmap SignKeyHashedSingleKES <$> rawDeserialiseSignKeyDSIGNMWith allocator bs

--
-- FixedSizeCodec instances
--

instance HashAlgorithm h => FixedSizeCodec (VerKeyKES (HashedSingleKES h d)) where
  type FixedSize (VerKeyKES (HashedSingleKES h d)) = HashSize h
  rawEncodeFixedSized (VerKeyHashedSingleKES vk) = hashToBytes vk
  rawDecodeFixedSized bs = VerKeyHashedSingleKES <$> hashFromByteStringM bs
  {-# INLINE rawDecodeFixedSized #-}

instance
  (DSIGNAlgorithm d, KnownNat (SigSizeDSIGN d + VerKeySizeDSIGN d), Typeable h) =>
  FixedSizeCodec (SigKES (HashedSingleKES h d))
  where
  type FixedSize (SigKES (HashedSingleKES h d)) = SigSizeDSIGN d + VerKeySizeDSIGN d
  rawEncodeFixedSized (SigHashedSingleKES sig vk) =
    rawEncodeFixedSized sig <> rawEncodeFixedSized vk
  rawDecodeFixedSized b = guardFixedSized b $ do
    sigma <- rawDecodeFixedSized b_sig
    vk <- rawDecodeFixedSized b_vk
    return (SigHashedSingleKES sigma vk)
    where
      b_sig = slice off_sig size_sig b
      b_vk = slice off_vk size_vk b

      size_sig = fixedSize (Proxy :: Proxy (SigDSIGN d))
      size_vk = fixedSize (Proxy :: Proxy (VerKeyDSIGN d))

      off_sig = 0 :: Word
      off_vk = size_sig
  {-# INLINE rawDecodeFixedSized #-}

instance
  DSIGNAlgorithm d =>
  FixedSizeCodec (UnsoundPureSignKeyKES (HashedSingleKES h d))
  where
  type FixedSize (UnsoundPureSignKeyKES (HashedSingleKES h d)) = SignKeySizeKES (HashedSingleKES h d)
  rawEncodeFixedSized (UnsoundPureSignKeyHashedSingleKES sk) = rawEncodeFixedSized sk
  rawDecodeFixedSized bs = UnsoundPureSignKeyHashedSingleKES <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

--
-- VerKey instances
--

deriving instance HashAlgorithm h => Show (VerKeyKES (HashedSingleKES h d))
deriving instance Eq (VerKeyKES (HashedSingleKES h d))

instance
  KESAlgorithm (HashedSingleKES h d) =>
  ToCBOR (VerKeyKES (HashedSingleKES h d))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance
  KESAlgorithm (HashedSingleKES h d) =>
  FromCBOR (VerKeyKES (HashedSingleKES h d))
  where
  fromCBOR = decodeFixedSized

instance NoThunks (VerKeyKES (HashedSingleKES h d))

--
-- SignKey instances
--

deriving via
  (SignKeyDSIGNM d)
  instance
    DSIGNMAlgorithm d => NoThunks (SignKeyKES (HashedSingleKES h d))

--
-- Sig instances
--

deriving instance DSIGNMAlgorithm d => Show (SigKES (HashedSingleKES h d))
deriving instance DSIGNMAlgorithm d => Eq (SigKES (HashedSingleKES h d))

instance DSIGNMAlgorithm d => NoThunks (SigKES (HashedSingleKES h d))

instance
  KESAlgorithm (HashedSingleKES h d) =>
  ToCBOR (SigKES (HashedSingleKES h d))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance
  KESAlgorithm (HashedSingleKES h d) =>
  FromCBOR (SigKES (HashedSingleKES h d))
  where
  fromCBOR = decodeFixedSized

--
-- UnsoundPureSignKey instances
--

deriving instance DSIGNAlgorithm d => Show (UnsoundPureSignKeyKES (HashedSingleKES h d))
deriving instance
  (DSIGNAlgorithm d, Eq (SignKeyDSIGN d)) => Eq (UnsoundPureSignKeyKES (HashedSingleKES h d))

instance
  (UnsoundDSIGNMAlgorithm d, KESAlgorithm (HashedSingleKES h d)) =>
  ToCBOR (UnsoundPureSignKeyKES (HashedSingleKES h d))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size _skProxy = encodedSignKeyKESSizeExpr (Proxy :: Proxy (SignKeyKES (HashedSingleKES h d)))

instance
  (UnsoundDSIGNMAlgorithm d, KESAlgorithm (HashedSingleKES h d)) =>
  FromCBOR (UnsoundPureSignKeyKES (HashedSingleKES h d))
  where
  fromCBOR = decodeFixedSized

instance DSIGNAlgorithm d => NoThunks (UnsoundPureSignKeyKES (HashedSingleKES h d))

--
-- Direct ser/deser
--

instance DirectSerialise (SignKeyDSIGNM d) => DirectSerialise (SignKeyKES (HashedSingleKES h d)) where
  directSerialise push (SignKeyHashedSingleKES sk) = directSerialise push sk

instance DirectDeserialise (SignKeyDSIGNM d) => DirectDeserialise (SignKeyKES (HashedSingleKES h d)) where
  directDeserialise pull = SignKeyHashedSingleKES <$!> directDeserialise pull

instance DirectSerialise (VerKeyKES (HashedSingleKES h d)) where
  directSerialise push (VerKeyHashedSingleKES h) =
    unpackByteStringCStringLen (hashToBytes h) $ \(ptr, len) ->
      push (castPtr ptr) (fromIntegral @Int @CSize len)

instance
  HashAlgorithm h =>
  DirectDeserialise (VerKeyKES (HashedSingleKES h d))
  where
  directDeserialise pull = do
    let len = fromIntegral @Word @Int $ hashSize (Proxy @h)
    fptr <- mallocForeignPtrBytes len
    withForeignPtr fptr $ \ptr -> do
      pull (castPtr ptr) (fromIntegral @Int @CSize len)
    let bs = BS.fromForeignPtr (unsafeRawForeignPtr fptr) 0 len
    maybe (error "Invalid hash") return $! VerKeyHashedSingleKES <$!> hashFromBytes bs
