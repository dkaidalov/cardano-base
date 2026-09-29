{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NoStarIsType #-}

-- | A benchmarking wrapper around any KES scheme that adds two independent
-- knobs to its signatures:
--
-- * @pad@ zero bytes appended to every signature. Signing appends them,
--   verification checks and strips them. This lets a block header carry the
--   bytes a different (for example post-quantum) operational certificate or
--   signature scheme would add, without changing the header type or the
--   ledger.
-- * @spinUs@ microseconds of busy waiting after each successful
--   verification, so verification cost can be varied independently of size.
--   The spin is a monotonic-clock loop, not a 'threadDelay', because
--   'verifyKES' is pure and its callers in consensus run in 'Except'.
--
-- Everything else (keys, key evolution, serialisation of keys) passes
-- through to the wrapped scheme unchanged, so
-- @PaddedKES 0 0 k@ is observationally @k@ with a longer algorithm name.
--
-- This module exists for network experiments. It is not a signature scheme
-- and must not be used outside a test network.
module Cardano.Crypto.KES.Padded (
  PaddedKES,
  VerKeyKES (..),
  SignKeyKES (..),
  SigKES (..),
  UnsoundPureSignKeyKES (..),
  paddingSizeKES,
  spinMicrosKES,
) where

import Control.DeepSeq (NFData)
import Control.Monad (unless, (<$!>))
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable)
import Data.Word (Word64)
import GHC.Clock (getMonotonicTimeNSec)
import GHC.Generics (Generic)
import GHC.TypeLits (KnownNat, Nat, natVal, type (+))
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafePerformIO)

import Cardano.Base.Bytes (slice)
import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  guardFixedSized,
 )
import Cardano.Crypto.DirectSerialise
import Cardano.Crypto.KES.Class

-- | @PaddedKES pad spinUs k@: the scheme @k@ with @pad@ extra signature
-- bytes and a @spinUs@ microsecond verification delay.
data PaddedKES (pad :: Nat) (spinUs :: Nat) k

-- | The number of padding bytes, as a value.
paddingSizeKES :: forall pad spinUs k proxy. KnownNat pad => proxy (PaddedKES pad spinUs k) -> Word
paddingSizeKES _ = fromInteger (natVal (Proxy @pad))

-- | The verification delay in microseconds, as a value.
spinMicrosKES :: forall pad spinUs k proxy. KnownNat spinUs => proxy (PaddedKES pad spinUs k) -> Word64
spinMicrosKES _ = fromInteger (natVal (Proxy @spinUs))

-- | Busy-wait for the given number of microseconds. The 'ByteString'
-- argument is unused except to give the call a data dependency on the
-- signature being verified, so GHC cannot share one evaluation across
-- verifications. Zero microseconds returns immediately.
{-# NOINLINE busySpin #-}
busySpin :: Word64 -> BS.ByteString -> Either String ()
busySpin 0 _ = Right ()
busySpin us bs = unsafePerformIO $ do
  start <- getMonotonicTimeNSec
  let deadline = start + us * 1000
      loop = do
        now <- getMonotonicTimeNSec
        unless (now >= deadline) loop
  loop
  return $! if BS.length bs < 0 then Left "busySpin: impossible" else Right ()

instance
  ( KESAlgorithm k
  , KnownNat pad
  , KnownNat spinUs
  , KnownNat (FixedSize (SigKES k) + pad)
  ) =>
  KESAlgorithm (PaddedKES pad spinUs k)
  where
  type SeedSizeKES (PaddedKES pad spinUs k) = SeedSizeKES k

  newtype VerKeyKES (PaddedKES pad spinUs k) = VerKeyPaddedKES (VerKeyKES k)
    deriving (Generic)

  newtype SigKES (PaddedKES pad spinUs k) = SigPaddedKES (SigKES k)
    deriving (Generic)

  newtype SignKeyKES (PaddedKES pad spinUs k) = SignKeyPaddedKES (SignKeyKES k)

  type ContextKES (PaddedKES pad spinUs k) = ContextKES k
  type Signable (PaddedKES pad spinUs k) = Signable k
  type TotalPeriodsKES (PaddedKES pad spinUs k) = TotalPeriodsKES k
  type SignKeySizeKES (PaddedKES pad spinUs k) = SignKeySizeKES k

  algorithmNameKES _ =
    algorithmNameKES (Proxy :: Proxy k)
      ++ "_pad"
      ++ show (natVal (Proxy @pad))
      ++ "_spin"
      ++ show (natVal (Proxy @spinUs))
      ++ "us"

  -- The verification key bytes are the inner key's, so the default
  -- 'hashVerKeyKES' hashes exactly what the inner scheme would.

  verifyKES ctxt (VerKeyPaddedKES vk) t a (SigPaddedKES sig) = do
    verifyKES ctxt vk t a sig
    busySpin (fromInteger (natVal (Proxy @spinUs))) (rawEncodeFixedSized sig)

  deriveVerKeyKES (SignKeyPaddedKES sk) = VerKeyPaddedKES <$!> deriveVerKeyKES sk

  signKES ctxt t a (SignKeyPaddedKES sk) = SigPaddedKES <$!> signKES ctxt t a sk

  updateKESWith allocator ctxt (SignKeyPaddedKES sk) t =
    fmap SignKeyPaddedKES <$!> updateKESWith allocator ctxt sk t

  genKeyKESWith allocator seed = SignKeyPaddedKES <$!> genKeyKESWith allocator seed

  forgetSignKeyKESWith allocator (SignKeyPaddedKES sk) = forgetSignKeyKESWith allocator sk

instance
  ( KESAlgorithm (PaddedKES pad spinUs k)
  , UnsoundPureKESAlgorithm k
  ) =>
  UnsoundPureKESAlgorithm (PaddedKES pad spinUs k)
  where
  newtype UnsoundPureSignKeyKES (PaddedKES pad spinUs k)
    = UnsoundPureSignKeyPaddedKES (UnsoundPureSignKeyKES k)
    deriving (Generic)

  unsoundPureSignKES ctxt t a (UnsoundPureSignKeyPaddedKES sk) =
    SigPaddedKES $! unsoundPureSignKES ctxt t a sk
  unsoundPureUpdateKES ctxt (UnsoundPureSignKeyPaddedKES sk) t =
    UnsoundPureSignKeyPaddedKES <$!> unsoundPureUpdateKES ctxt sk t
  unsoundPureGenKeyKES seed = UnsoundPureSignKeyPaddedKES $! unsoundPureGenKeyKES seed
  unsoundPureDeriveVerKeyKES (UnsoundPureSignKeyPaddedKES sk) =
    VerKeyPaddedKES $! unsoundPureDeriveVerKeyKES sk
  unsoundPureSignKeyKESToSoundSignKeyKES (UnsoundPureSignKeyPaddedKES sk) =
    SignKeyPaddedKES <$!> unsoundPureSignKeyKESToSoundSignKeyKES sk

instance
  ( KESAlgorithm (PaddedKES pad spinUs k)
  , UnsoundKESAlgorithm k
  ) =>
  UnsoundKESAlgorithm (PaddedKES pad spinUs k)
  where
  rawSerialiseSignKeyKES (SignKeyPaddedKES sk) = rawSerialiseSignKeyKES sk
  rawDeserialiseSignKeyKESWith allocator bs =
    fmap SignKeyPaddedKES <$!> rawDeserialiseSignKeyKESWith allocator bs

--
-- Fixed-size codecs
--

instance FixedSizeCodec (VerKeyKES k) => FixedSizeCodec (VerKeyKES (PaddedKES pad spinUs k)) where
  type FixedSize (VerKeyKES (PaddedKES pad spinUs k)) = FixedSize (VerKeyKES k)
  rawEncodeFixedSized (VerKeyPaddedKES vk) = rawEncodeFixedSized vk
  rawDecodeFixedSized bs = VerKeyPaddedKES <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance
  ( FixedSizeCodec (SigKES k)
  , KnownNat pad
  , KnownNat (FixedSize (SigKES k) + pad)
  , Typeable k
  , Typeable pad
  , Typeable spinUs
  ) =>
  FixedSizeCodec (SigKES (PaddedKES pad spinUs k))
  where
  type FixedSize (SigKES (PaddedKES pad spinUs k)) = FixedSize (SigKES k) + pad
  rawEncodeFixedSized (SigPaddedKES sig) =
    rawEncodeFixedSized sig <> BS.replicate (fromInteger (natVal (Proxy @pad))) 0
  rawDecodeFixedSized b = guardFixedSized b $ do
    unless (BS.all (== 0) b_pad) $ fail "PaddedKES: non-zero padding"
    SigPaddedKES <$> rawDecodeFixedSized b_sig
    where
      size_sig = fixedSize (Proxy :: Proxy (SigKES k))
      size_pad = fromInteger (natVal (Proxy @pad)) :: Word
      b_sig = slice 0 size_sig b
      b_pad = slice size_sig size_pad b
  {-# INLINE rawDecodeFixedSized #-}

instance
  FixedSizeCodec (UnsoundPureSignKeyKES k) =>
  FixedSizeCodec (UnsoundPureSignKeyKES (PaddedKES pad spinUs k))
  where
  type FixedSize (UnsoundPureSignKeyKES (PaddedKES pad spinUs k)) = FixedSize (UnsoundPureSignKeyKES k)
  rawEncodeFixedSized (UnsoundPureSignKeyPaddedKES sk) = rawEncodeFixedSized sk
  rawDecodeFixedSized bs = UnsoundPureSignKeyPaddedKES <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

--
-- VerKey instances
--

deriving newtype instance Show (VerKeyKES k) => Show (VerKeyKES (PaddedKES pad spinUs k))
deriving newtype instance Eq (VerKeyKES k) => Eq (VerKeyKES (PaddedKES pad spinUs k))
deriving newtype instance NoThunks (VerKeyKES k) => NoThunks (VerKeyKES (PaddedKES pad spinUs k))
deriving newtype instance NFData (VerKeyKES k) => NFData (VerKeyKES (PaddedKES pad spinUs k))

instance KESAlgorithm (PaddedKES pad spinUs k) => ToCBOR (VerKeyKES (PaddedKES pad spinUs k)) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance KESAlgorithm (PaddedKES pad spinUs k) => FromCBOR (VerKeyKES (PaddedKES pad spinUs k)) where
  fromCBOR = decodeFixedSized

instance DirectSerialise (VerKeyKES k) => DirectSerialise (VerKeyKES (PaddedKES pad spinUs k)) where
  directSerialise push (VerKeyPaddedKES vk) = directSerialise push vk

instance DirectDeserialise (VerKeyKES k) => DirectDeserialise (VerKeyKES (PaddedKES pad spinUs k)) where
  directDeserialise pull = VerKeyPaddedKES <$!> directDeserialise pull

--
-- SignKey instances
--

deriving newtype instance NoThunks (SignKeyKES k) => NoThunks (SignKeyKES (PaddedKES pad spinUs k))
deriving newtype instance NFData (SignKeyKES k) => NFData (SignKeyKES (PaddedKES pad spinUs k))

instance DirectSerialise (SignKeyKES k) => DirectSerialise (SignKeyKES (PaddedKES pad spinUs k)) where
  directSerialise push (SignKeyPaddedKES sk) = directSerialise push sk

instance DirectDeserialise (SignKeyKES k) => DirectDeserialise (SignKeyKES (PaddedKES pad spinUs k)) where
  directDeserialise pull = SignKeyPaddedKES <$!> directDeserialise pull

--
-- Sig instances
--

deriving newtype instance Show (SigKES k) => Show (SigKES (PaddedKES pad spinUs k))
deriving newtype instance Eq (SigKES k) => Eq (SigKES (PaddedKES pad spinUs k))
deriving newtype instance NoThunks (SigKES k) => NoThunks (SigKES (PaddedKES pad spinUs k))
deriving newtype instance NFData (SigKES k) => NFData (SigKES (PaddedKES pad spinUs k))

instance KESAlgorithm (PaddedKES pad spinUs k) => ToCBOR (SigKES (PaddedKES pad spinUs k)) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance KESAlgorithm (PaddedKES pad spinUs k) => FromCBOR (SigKES (PaddedKES pad spinUs k)) where
  fromCBOR = decodeFixedSized

--
-- UnsoundPureSignKey instances
--

deriving newtype instance
  Show (UnsoundPureSignKeyKES k) => Show (UnsoundPureSignKeyKES (PaddedKES pad spinUs k))
deriving newtype instance
  Eq (UnsoundPureSignKeyKES k) => Eq (UnsoundPureSignKeyKES (PaddedKES pad spinUs k))
deriving newtype instance
  NoThunks (UnsoundPureSignKeyKES k) => NoThunks (UnsoundPureSignKeyKES (PaddedKES pad spinUs k))

instance
  UnsoundPureKESAlgorithm (PaddedKES pad spinUs k) =>
  ToCBOR (UnsoundPureSignKeyKES (PaddedKES pad spinUs k))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size _skProxy =
    encodedSignKeyKESSizeExpr (Proxy :: Proxy (SignKeyKES (PaddedKES pad spinUs k)))

instance
  UnsoundPureKESAlgorithm (PaddedKES pad spinUs k) =>
  FromCBOR (UnsoundPureSignKeyKES (PaddedKES pad spinUs k))
  where
  fromCBOR = decodeFixedSized
