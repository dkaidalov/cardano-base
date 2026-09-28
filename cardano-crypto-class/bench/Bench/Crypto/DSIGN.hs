{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

{- FOURMOLU_DISABLE -}

module Bench.Crypto.DSIGN
  ( benchmarks
  ) where

import Data.Proxy
import Data.ByteString (ByteString)
import qualified Data.Foldable as F

import Control.DeepSeq
import Control.Exception (evaluate)

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.DSIGN.Ed25519
import Cardano.Crypto.DSIGN.Falcon512
import Cardano.Crypto.DSIGN.MLDSA44
#ifdef SECP256K1_ENABLED
import Cardano.Crypto.DSIGN.EcdsaSecp256k1
import Cardano.Crypto.DSIGN.SchnorrSecp256k1
import Cardano.Crypto.Hash.Blake2b
#endif

import Criterion

import Bench.Crypto.BenchData
import Cardano.Crypto.DSIGN.BLS12381.Internal (BLS12381MinSigDSIGN, BLS12381MinVerKeyDSIGN, BLS12381DSIGN)

benchmarks :: Benchmark
benchmarks = bgroup "DSIGN"
  [ benchDSIGN (Proxy :: Proxy Ed25519DSIGN) "Ed25519"
  , benchDSIGN (Proxy :: Proxy MLDSA44DSIGN) "MLDSA44"
  , benchDSIGN (Proxy :: Proxy Falcon512DSIGN) "Falcon512"
  , benchDSIGN (Proxy :: Proxy BLS12381MinVerKeyDSIGN) "BLS12381MinVerKey"
  , benchDSIGN (Proxy :: Proxy BLS12381MinSigDSIGN) "BLS12381MinSig"
  , benchAggDSIGN (Proxy :: Proxy BLS12381MinVerKeyDSIGN) "BLS12381MinVerKey"
  , benchAggDSIGN (Proxy :: Proxy BLS12381MinSigDSIGN) "BLS12381MinSig"
#ifdef SECP256K1_ENABLED
  , benchDSIGN (Proxy :: Proxy EcdsaSecp256k1DSIGN) "EcdsaSecp256k1"
  , benchDSIGN (Proxy :: Proxy SchnorrSecp256k1DSIGN) "SchnorrSecp256k1"
#endif
  ]

-- | Benchmark key generation, signing and verification for one scheme.
--
-- Signing and verification cycle through 'typicalMsgs' with 'perRunEnv', so
-- that each run signs (or verifies) a different message. For schemes with
-- rejection sampling the signing time depends on the message, and timing a
-- single fixed one would report the cost of that input rather than of the
-- scheme; see 'typicalMsgCount'.
benchDSIGN :: forall v a
           . ( DSIGNAlgorithm v
             , Signable v a
             , ExampleSignable v a
             , ExampleContext v
             , NFData a
             , NFData (SignKeyDSIGN v)
             , NFData (VerKeyDSIGN v)
             , NFData (SigDSIGN v)
             )
          => Proxy v
          -> String
          -> Benchmark
benchDSIGN _ lbl =
  let msgs = exampleSignables (Proxy @v)
      ctx = exampleContext (Proxy @v)
  in
  bgroup lbl
    [ bench "genKeyDSIGN" $
        nf (genKeyDSIGN @v) testSeed

    , env (do let signKey = genKeyDSIGN @v testSeed
              nextMsg <- newInputCycle msgs
              return (signKey, nextMsg)
          ) $ \ ~(signKey, nextMsg) ->
      bench "signDSIGN" $
        perRunEnv (nextInput nextMsg) $ \msg ->
          return $! signDSIGN @v ctx msg signKey

    , env (do let signKey = genKeyDSIGN @v testSeed
                  verKey  = deriveVerKeyDSIGN signKey
              pairs <- evaluate $ force [ (msg, signDSIGN @v ctx msg signKey) | msg <- msgs ]
              nextPair <- newInputCycle pairs
              return (verKey, nextPair)
          ) $ \ ~(verKey, nextPair) ->
      bench "verifyDSIGN" $
        perRunEnv (nextInput nextPair) $ \ ~(msg, sig) ->
          return $! verifyDSIGN @v ctx verKey msg sig
    ]

-- | A helper class to gloss over the differences in the 'Signable' constraint
-- for different 'DSIGNAlgorithm' instances. Some use 'ByteString', some use
-- 'MessageHash'.
class ExampleSignable v a | v -> a where
  -- | Turn one of the benchmark messages into the scheme's signable input.
  exampleSignableFrom :: Signable v a => Proxy v -> ByteString -> a

-- | The single input used where a benchmark needs only one message.
exampleSignable :: (ExampleSignable v a, Signable v a) => Proxy v -> a
exampleSignable p = exampleSignableFrom p typicalMsg

-- | The inputs the sign and verify benchmarks cycle through.
exampleSignables :: (ExampleSignable v a, Signable v a) => Proxy v -> [a]
exampleSignables p = map (exampleSignableFrom p) typicalMsgs

instance ExampleSignable Ed25519DSIGN ByteString where
  exampleSignableFrom _ = id

instance ExampleSignable MLDSA44DSIGN ByteString where
  exampleSignableFrom _ = id

instance ExampleSignable Falcon512DSIGN ByteString where
  exampleSignableFrom _ = id

instance ExampleSignable (BLS12381DSIGN curve) ByteString where
  exampleSignableFrom _ = id

#ifdef SECP256K1_ENABLED
instance ExampleSignable EcdsaSecp256k1DSIGN MessageHash where
  exampleSignableFrom _ = hashAndPack (Proxy @Blake2b_256)

instance ExampleSignable SchnorrSecp256k1DSIGN ByteString where
  exampleSignableFrom _ = id
#endif

-- | Provide an example context for each DSIGN algorithm.
-- similar to 'ExampleSignable', this glosses over differences in the
-- 'ContextDSIGN' associated type.
class ExampleContext v where
  exampleContext :: Proxy v -> ContextDSIGN v

instance ExampleContext Ed25519DSIGN where
  exampleContext _ = ()

instance ExampleContext MLDSA44DSIGN where
  exampleContext _ = ()

instance ExampleContext Falcon512DSIGN where
  exampleContext _ = ()

#ifdef SECP256K1_ENABLED
instance ExampleContext EcdsaSecp256k1DSIGN where
  exampleContext _ = ()

instance ExampleContext SchnorrSecp256k1DSIGN where
  exampleContext _ = ()
#endif

instance ExampleContext (BLS12381DSIGN curve) where
  exampleContext _ = ()

benchAggDSIGN :: forall v a
  . ( DSIGNAggregatable v
    , Signable v a
    , ExampleSignable v a
    , ExampleContext v
    , NFData (SignKeyDSIGN v)
    , NFData (VerKeyDSIGN v)
    , NFData (SigDSIGN v)
    , NFData (PossessionProofDSIGN v)
    )
  => Proxy v
  -> String
  -> Benchmark
benchAggDSIGN _ lbl =
  let msg = exampleSignable (Proxy @v)
      ctx = exampleContext (Proxy @v)
      ns = 1 : [100, 200, 300]
  in bgroup (lbl <> "/Aggregatable") $
      [ bgroup ("n=" <> show n)
          [ env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "provePoP (all)" $
                nf (proveAllPoPs @v) (caseSKs c)

          , env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "verifyPoP (all)" $
                nf (verifyAllPoPs @v) (caseVKPoPs c)

          , env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "aggregateVerKeys (with PoPs)" $
                nf (aggregateVerKeysDSIGN @v) (caseVKPoPs c)

          , env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "aggregateVerKeys (no PoPs)" $
                nf (uncheckedAggregateVerKeysDSIGN @v) (caseVKs c)

          , env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "aggregateSig" $
                nf (aggregateSigsDSIGN @v) (caseSigs c)
          ]
      | n <- ns
      ]

data AggCase v = AggCase
  { caseSKs    :: ![SignKeyDSIGN v]
  , caseVKs    :: ![VerKeyDSIGN v]
  , caseVKPoPs :: ![(VerKeyDSIGN v, PossessionProofDSIGN v)]
  , caseSigs   :: ![SigDSIGN v]
  }

instance
  ( NFData (SignKeyDSIGN v)
  , NFData (VerKeyDSIGN v)
  , NFData (PossessionProofDSIGN v)
  , NFData (SigDSIGN v)
  ) => NFData (AggCase v) where
  rnf (AggCase sks vks vkp sigs) =
    rnf sks `seq`
    rnf vks `seq`
    rnf vkp `seq`
    rnf sigs

mkCase :: forall v a. (DSIGNAggregatable v, Signable v a)
  => ContextDSIGN v -> a -> Int -> AggCase v
mkCase ctx msg n =
  let sks  = replicate n (genKeyDSIGN @v testSeed)
      vks  = map deriveVerKeyDSIGN sks
      pops = map (createPossessionProofDSIGN @v) sks
      sigs = map (signDSIGN @v ctx msg) sks
      vkp  = zip vks pops
  in AggCase sks vks vkp sigs

proveAllPoPs :: forall v. DSIGNAggregatable v
  => [SignKeyDSIGN v] -> [PossessionProofDSIGN v]
proveAllPoPs = map (createPossessionProofDSIGN @v)

verifyAllPoPs :: forall v. DSIGNAggregatable v
  => [(VerKeyDSIGN v, PossessionProofDSIGN v)]
  -> Either String ()
verifyAllPoPs = F.foldl' (\acc (vk,pop) -> acc >> verifyPossessionProofDSIGN @v vk pop) (Right ())
