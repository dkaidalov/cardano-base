{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NoStarIsType #-}

-- | A benchmarking wrapper around any VRF that appends @pad@ zero bytes to
-- every proof. Evaluation appends them, verification checks and strips them,
-- and keys and outputs pass through to the wrapped scheme unchanged, so
-- @PaddedVRF 0 v@ is observationally @v@ with a longer algorithm name.
--
-- Its purpose is to give a test network's block headers the proof size a
-- post-quantum VRF would have, before any such VRF exists, without changing
-- the header type or the ledger. Cardano's Praos header carries the VRF
-- proof in every block, so this is the knob for the proof-size budget
-- question.
--
-- This module exists for network experiments. It adds no security and must
-- not be used outside a test network.
module Cardano.Crypto.VRF.Padded (
  PaddedVRF,
  VerKeyVRF (..),
  SignKeyVRF (..),
  CertVRF (..),
  paddingSizeVRF,
) where

import Control.DeepSeq (NFData)
import Control.Monad (unless)
import qualified Data.ByteString as BS
import Data.Coerce (coerce)
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import GHC.TypeLits (KnownNat, Nat, natVal, type (+))
import NoThunks.Class (NoThunks)

import Cardano.Base.Bytes (slice)
import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  fixedSize,
  guardFixedSized,
 )
import Cardano.Crypto.VRF.Class

-- | @PaddedVRF pad v@: the VRF @v@ with @pad@ extra proof bytes.
data PaddedVRF (pad :: Nat) v

-- | The number of padding bytes, as a value.
paddingSizeVRF :: forall pad v proxy. KnownNat pad => proxy (PaddedVRF pad v) -> Word
paddingSizeVRF _ = fromInteger (natVal (Proxy @pad))

instance
  ( VRFAlgorithm v
  , KnownNat pad
  , KnownNat (FixedSize (CertVRF v) + pad)
  ) =>
  VRFAlgorithm (PaddedVRF pad v)
  where
  newtype VerKeyVRF (PaddedVRF pad v) = VerKeyPaddedVRF (VerKeyVRF v)
    deriving (Generic)
  newtype SignKeyVRF (PaddedVRF pad v) = SignKeyPaddedVRF (SignKeyVRF v)
    deriving (Generic)
  newtype CertVRF (PaddedVRF pad v) = CertPaddedVRF (CertVRF v)
    deriving (Generic)

  type ContextVRF (PaddedVRF pad v) = ContextVRF v
  type Signable (PaddedVRF pad v) = Signable v

  algorithmNameVRF _ =
    algorithmNameVRF (Proxy :: Proxy v) ++ "_pad" ++ show (natVal (Proxy @pad))

  -- The verification key bytes are the inner key's, so the default
  -- 'hashVerKeyVRF' hashes exactly what the inner scheme would.

  deriveVerKeyVRF (SignKeyPaddedVRF sk) = VerKeyPaddedVRF (deriveVerKeyVRF sk)

  evalVRF ctxt a (SignKeyPaddedVRF sk) =
    let (out, cert) = evalVRF ctxt a sk
     in (coerce out, CertPaddedVRF cert)

  verifyVRF ctxt (VerKeyPaddedVRF vk) a (CertPaddedVRF cert) =
    coerce <$> verifyVRF ctxt vk a cert

  genKeyVRF seed = SignKeyPaddedVRF (genKeyVRF seed)
  genKeyPairVRF seed =
    let (sk, vk) = genKeyPairVRF seed
     in (SignKeyPaddedVRF sk, VerKeyPaddedVRF vk)

  seedSizeVRF _ = seedSizeVRF (Proxy :: Proxy v)
  sizeOutputVRF _ = sizeOutputVRF (Proxy :: Proxy v)

--
-- Fixed-size codecs
--

instance FixedSizeCodec (VerKeyVRF v) => FixedSizeCodec (VerKeyVRF (PaddedVRF pad v)) where
  type FixedSize (VerKeyVRF (PaddedVRF pad v)) = FixedSize (VerKeyVRF v)
  rawEncodeFixedSized (VerKeyPaddedVRF vk) = rawEncodeFixedSized vk
  rawDecodeFixedSized bs = VerKeyPaddedVRF <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyVRF v) => FixedSizeCodec (SignKeyVRF (PaddedVRF pad v)) where
  type FixedSize (SignKeyVRF (PaddedVRF pad v)) = FixedSize (SignKeyVRF v)
  rawEncodeFixedSized (SignKeyPaddedVRF sk) = rawEncodeFixedSized sk
  rawDecodeFixedSized bs = SignKeyPaddedVRF <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance
  ( FixedSizeCodec (CertVRF v)
  , KnownNat pad
  , KnownNat (FixedSize (CertVRF v) + pad)
  , Typeable v
  , Typeable pad
  ) =>
  FixedSizeCodec (CertVRF (PaddedVRF pad v))
  where
  type FixedSize (CertVRF (PaddedVRF pad v)) = FixedSize (CertVRF v) + pad
  rawEncodeFixedSized (CertPaddedVRF cert) =
    rawEncodeFixedSized cert <> BS.replicate (fromInteger (natVal (Proxy @pad))) 0
  rawDecodeFixedSized b = guardFixedSized b $ do
    unless (BS.all (== 0) b_pad) $ fail "PaddedVRF: non-zero padding"
    CertPaddedVRF <$> rawDecodeFixedSized b_cert
    where
      size_cert = fixedSize (Proxy :: Proxy (CertVRF v))
      size_pad = fromInteger (natVal (Proxy @pad)) :: Word
      b_cert = slice 0 size_cert b
      b_pad = slice size_cert size_pad b
  {-# INLINE rawDecodeFixedSized #-}

--
-- Pass-through instances
--

deriving newtype instance Show (VerKeyVRF v) => Show (VerKeyVRF (PaddedVRF pad v))
deriving newtype instance Eq (VerKeyVRF v) => Eq (VerKeyVRF (PaddedVRF pad v))
deriving newtype instance NoThunks (VerKeyVRF v) => NoThunks (VerKeyVRF (PaddedVRF pad v))
deriving newtype instance NFData (VerKeyVRF v) => NFData (VerKeyVRF (PaddedVRF pad v))

deriving newtype instance Show (SignKeyVRF v) => Show (SignKeyVRF (PaddedVRF pad v))
deriving newtype instance Eq (SignKeyVRF v) => Eq (SignKeyVRF (PaddedVRF pad v))
deriving newtype instance NoThunks (SignKeyVRF v) => NoThunks (SignKeyVRF (PaddedVRF pad v))
deriving newtype instance NFData (SignKeyVRF v) => NFData (SignKeyVRF (PaddedVRF pad v))

deriving newtype instance Show (CertVRF v) => Show (CertVRF (PaddedVRF pad v))
deriving newtype instance Eq (CertVRF v) => Eq (CertVRF (PaddedVRF pad v))
deriving newtype instance Ord (CertVRF v) => Ord (CertVRF (PaddedVRF pad v))
deriving newtype instance NoThunks (CertVRF v) => NoThunks (CertVRF (PaddedVRF pad v))
deriving newtype instance NFData (CertVRF v) => NFData (CertVRF (PaddedVRF pad v))

instance VRFAlgorithm (PaddedVRF pad v) => ToCBOR (VerKeyVRF (PaddedVRF pad v)) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedVerKeyVRFSizeExpr

instance VRFAlgorithm (PaddedVRF pad v) => FromCBOR (VerKeyVRF (PaddedVRF pad v)) where
  fromCBOR = decodeFixedSized

instance VRFAlgorithm (PaddedVRF pad v) => ToCBOR (SignKeyVRF (PaddedVRF pad v)) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedSignKeyVRFSizeExpr

instance VRFAlgorithm (PaddedVRF pad v) => FromCBOR (SignKeyVRF (PaddedVRF pad v)) where
  fromCBOR = decodeFixedSized

instance VRFAlgorithm (PaddedVRF pad v) => ToCBOR (CertVRF (PaddedVRF pad v)) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedCertVRFSizeExpr

instance VRFAlgorithm (PaddedVRF pad v) => FromCBOR (CertVRF (PaddedVRF pad v)) where
  fromCBOR = decodeFixedSized
