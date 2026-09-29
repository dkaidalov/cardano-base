{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Bench.Crypto.KES (
  benchmarks,
) where

import Data.Maybe (fromJust)
import Data.Proxy

import Control.DeepSeq
import Control.Exception (evaluate)

import Cardano.Crypto.DSIGN.Ed25519
import Cardano.Crypto.DSIGN.Falcon512
import Cardano.Crypto.DSIGN.MLDSA44
import Cardano.Crypto.DSIGN.SlhDsaBb6
import Cardano.Crypto.DSIGN.XmssMock
import Cardano.Crypto.Hash.Blake2b
import Cardano.Crypto.KES.Class
import Cardano.Crypto.KES.CompactSum
import Cardano.Crypto.KES.HashedSingle
import Cardano.Crypto.KES.Sum

import Cardano.Crypto.Libsodium as NaCl
import Cardano.Crypto.Libsodium.MLockedSeed
import Criterion
import qualified Data.ByteString as BS (ByteString)
import Data.Kind (Type)
import GHC.TypeLits (KnownNat)
import System.IO.Unsafe (unsafePerformIO)

import Bench.Crypto.BenchData

{- HLINT ignore "Use camelCase" -}

{-# NOINLINE testSeedML #-}
testSeedML :: forall n. KnownNat n => MLockedSeed n
testSeedML = MLockedSeed . unsafePerformIO $ NaCl.mlsbFromByteString testBytes

benchmarks :: Benchmark
benchmarks =
  bgroup
    "KES"
    [ benchKES @Proxy @(Sum6KES Ed25519DSIGN Blake2b_256) Proxy "Sum6KES"
    , benchKES @Proxy @(Sum7KES Ed25519DSIGN Blake2b_256) Proxy "Sum7KES"
    , benchKES @Proxy @(CompactSum6KES Ed25519DSIGN Blake2b_256) Proxy "CompactSum6KES"
    , benchKES @Proxy @(CompactSum7KES Ed25519DSIGN Blake2b_256) Proxy "CompactSum7KES"
    , benchKES @Proxy @(Sum6KES MLDSA44DSIGN Blake2b_256) Proxy "Sum6KES MLDSA44"
    , benchKES @Proxy @(CompactSum6KES MLDSA44DSIGN Blake2b_256) Proxy "CompactSum6KES MLDSA44"
    , benchKES @Proxy @(HashedCompactSum6KES MLDSA44DSIGN Blake2b_256)
        Proxy
        "HashedCompactSum6KES MLDSA44"
    , benchKES @Proxy @(HashedCompactSum6KES Falcon512DSIGN Blake2b_256)
        Proxy
        "HashedCompactSum6KES Falcon512"
    , benchKES @Proxy @(HashedCompactSum6KES SlhDsaBb6DSIGN Blake2b_256)
        Proxy
        "HashedCompactSum6KES SlhDsaBb6"
    , -- The XMSS mock consumes a one-time key per signKES and has 1023 of
      -- them; the sign and verify rows cycle sixteen keys (over 16000
      -- signatures, more than Criterion's runs at this speed), see
      -- 'benchKESWith'.
      benchKESWith @Proxy @(HashedCompactSum6KES XmssMockDSIGN Blake2b_256)
        16
        Proxy
        "HashedCompactSum6KES XmssMock"
    ]

-- | Benchmark the four KES operations for one scheme.
--
-- Key generation is expensive for the sum compositions (2^depth base key
-- generations), so every input a benchmark needs is prepared in an 'env'
-- and only the operation under test runs inside the timed region.
--
-- Signing and verification cycle through 'typicalMsgs' with 'perRunEnv', so
-- that each run signs (or verifies) a different message. For a leaf scheme
-- with rejection sampling the signing time depends on the message, and a
-- single fixed one would report the cost of that input rather than of the
-- scheme; see 'typicalMsgCount'.
--
-- Key evolution is timed twice. Evolving from period 0 is the cheapest case:
-- one base key generation at the bottom of the tree. Evolving from the last
-- period of the first half regenerates the whole second-half subtree and is
-- the most expensive step of the key's lifetime.
{-# NOINLINE benchKES #-}
benchKES ::
  forall (proxy :: forall k. k -> Type) v.
  ( KESAlgorithm v
  , ContextKES v ~ ()
  , Signable v BS.ByteString
  , NFData (SignKeyKES v)
  , NFData (VerKeyKES v)
  , NFData (SigKES v)
  ) =>
  proxy v ->
  [Char] ->
  Benchmark
benchKES = benchKESWith 1

-- | As 'benchKES', with the number of sign keys the signKES row cycles
-- through and the verifyKES row's signatures are spread over. One key is
-- right for stateless leaves. A stateful leaf consumes a one-time key per
-- signature and refuses to sign once they are used up, so its rows spread
-- the signatures over several keys, each used at most
-- @typicalMsgCount - 1@ (1023) times per cycle; the keys are generated in
-- the 'env', outside the timed region. All keys come from the same seed, so
-- they share one verification key. Criterion's run count grows as the
-- operation gets faster, so the key count has to cover it.
{-# NOINLINE benchKESWith #-}
benchKESWith ::
  forall (proxy :: forall k. k -> Type) v.
  ( KESAlgorithm v
  , ContextKES v ~ ()
  , Signable v BS.ByteString
  , NFData (SignKeyKES v)
  , NFData (VerKeyKES v)
  , NFData (SigKES v)
  ) =>
  Int ->
  proxy v ->
  [Char] ->
  Benchmark
benchKESWith signKeyCount _ lbl =
  bgroup
    lbl
    [ bench "genKey" $
        nfIO $
          genKeyKES @v testSeedML >>= forgetSignKeyKES @v
    , env genSignKeysAndMsgs $ \nextKeyAndMsg ->
        bench "signKES" $
          perRunEnv (nextInput nextKeyAndMsg) $ \ ~(signKey, msg) ->
            signKES @v () 0 msg signKey
    , env genVerKeyAndSigs $ \ ~(verKey, nextPair) ->
        bench "verifyKES" $
          perRunEnv (nextInput nextPair) $ \ ~(msg, sig) ->
            return $! either error id (verifyKES @v () verKey 0 msg sig)
    , env (genKeyKES @v testSeedML) $ \signKey ->
        bench "updateKES" $
          nfIO $
            updateKES @v () signKey 0 >>= forgetSignKeyKES @v . fromJust
    , env (evolveTo worstPeriod =<< genKeyKES @v testSeedML) $ \signKey ->
        bench ("updateKES (period " ++ show worstPeriod ++ ")") $
          nfIO $
            updateKES @v () signKey worstPeriod >>= forgetSignKeyKES @v . fromJust
    ]
  where
    -- Pairs every message with one of the sign keys in turn. With one key
    -- the cycle is the message set; with k keys it is k * (typicalMsgCount
    -- - 1) long and each key is used 1023 times per cycle, which is what a
    -- 2^10 one-time-key leaf allows.
    genSignKeysAndMsgs :: IO (InputCycle (SignKeyKES v, BS.ByteString))
    genSignKeysAndMsgs = do
      signKeys <- mapM (const (genKeyKES @v testSeedML)) [1 .. signKeyCount]
      let msgs
            | signKeyCount == 1 = typicalMsgs
            | otherwise = take (typicalMsgCount - 1) typicalMsgs
      newInputCycle
        [ (signKeys !! (i `mod` signKeyCount), msg)
        | (i, msg) <- zip [0 :: Int ..] (concat (replicate signKeyCount msgs))
        ]

    genVerKeyAndSigs :: IO (VerKeyKES v, InputCycle (BS.ByteString, SigKES v))
    genVerKeyAndSigs = do
      signKeys <- mapM (const (genKeyKES @v testSeedML)) [1 .. signKeyCount]
      sigs <-
        mapM
          (\(i, msg) -> signKES @v () 0 msg (signKeys !! (i `mod` signKeyCount)))
          (zip [0 :: Int ..] typicalMsgs)
      verKey <- deriveVerKeyKES (head signKeys)
      mapM_ forgetSignKeyKES signKeys
      pairs <- evaluate $ force (zip typicalMsgs sigs)
      nextPair <- newInputCycle pairs
      return (verKey, nextPair)

    -- The evolution from this period to the next regenerates the largest
    -- subtree: for a sum composition with T periods, the step from T/2 - 1
    -- to T/2 generates a fresh key for the whole second half.
    worstPeriod :: Period
    worstPeriod = totalPeriodsKES (Proxy @v) `div` 2 - 1

    evolveTo :: Period -> SignKeyKES v -> IO (SignKeyKES v)
    evolveTo target = go 0
      where
        go t sk
          | t >= target = return sk
          | otherwise = do
              sk' <- fromJust <$> updateKES @v () sk t
              forgetSignKeyKES sk
              go (t + 1) sk'
