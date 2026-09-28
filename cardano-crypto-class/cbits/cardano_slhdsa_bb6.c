/*
 * See cardano_slhdsa_bb6.h. Key generation, signing and verification follow
 * the reference's sign.c, with randombytes() replaced (deterministic
 * signing, seed-derived key generation) so that sign.c and randombytes.c
 * need not be compiled. Compiled with -DPARAMS=cardano-bb6.
 */
#include <string.h>

#include "cardano_slhdsa_bb6.h"
#include "params.h"
#include "address.h"
#include "context.h"
#include "fors.h"
#include "hash.h"
#include "merkle.h"
#include "sha2.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

typedef char cardano_slhdsa_bb6_static_assert_pk
    [CARDANO_SLHDSA_BB6_PUBLICKEYBYTES == SPX_PK_BYTES ? 1 : -1];
typedef char cardano_slhdsa_bb6_static_assert_sk
    [CARDANO_SLHDSA_BB6_SECRETKEYBYTES == SPX_SK_BYTES ? 1 : -1];
typedef char cardano_slhdsa_bb6_static_assert_sig
    [CARDANO_SLHDSA_BB6_SIGBYTES == SPX_BYTES ? 1 : -1];

/* seed48 = SHA256(0x00 || seed32) || SHA256(0x01 || seed32)[0..16) */
static void expand_seed(uint8_t out[3 * SPX_N], const uint8_t seed[CARDANO_SLHDSA_BB6_SEEDBYTES])
{
  uint8_t buf[1 + CARDANO_SLHDSA_BB6_SEEDBYTES];
  uint8_t h[32];
  memcpy(buf + 1, seed, CARDANO_SLHDSA_BB6_SEEDBYTES);
  buf[0] = 0;
  sha256(out, buf, sizeof buf);
  buf[0] = 1;
  sha256(h, buf, sizeof buf);
  memcpy(out + 32, h, 3 * SPX_N - 32);
  memset(buf, 0, sizeof buf);
  memset(h, 0, sizeof h);
}

/* Reference crypto_sign_seed_keypair. sk = SK_SEED || SK_PRF || PUB_SEED || root,
 * pk = PUB_SEED || root. */
static int seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
  spx_ctx ctx;
  memcpy(sk, seed, 3 * SPX_N);
  memcpy(pk, sk + 2 * SPX_N, SPX_N);
  memcpy(ctx.pub_seed, pk, SPX_N);
  memcpy(ctx.sk_seed, sk, SPX_N);
  initialize_hash_function(&ctx);
  merkle_gen_root(sk + 3 * SPX_N, &ctx);
  memcpy(pk + SPX_N, sk + 3 * SPX_N, SPX_N);
  return 0;
}

int cardano_slhdsa_bb6_signkey_from_seed(
    uint8_t signkey[CARDANO_SLHDSA_BB6_SIGNKEYBYTES],
    const uint8_t seed[CARDANO_SLHDSA_BB6_SEEDBYTES])
{
  uint8_t tmp[CARDANO_SLHDSA_BB6_SEEDBYTES];
  uint8_t seed48[3 * SPX_N];
  int rc;
  memcpy(tmp, seed, sizeof tmp); /* seed may alias the destination */
  memcpy(signkey + CARDANO_SLHDSA_BB6_SIGNKEY_SEED_OFFSET, tmp, sizeof tmp);
  expand_seed(seed48, tmp);
  rc = seed_keypair(signkey + CARDANO_SLHDSA_BB6_SIGNKEY_PK_OFFSET,
                    signkey + CARDANO_SLHDSA_BB6_SIGNKEY_SK_OFFSET, seed48);
  memset(tmp, 0, sizeof tmp);
  memset(seed48, 0, sizeof seed48);
  return rc;
}

/* Reference crypto_sign_signature with opt_rand = PK.seed (FIPS 205
 * deterministic variant) instead of randombytes(). */
int cardano_slhdsa_bb6_sign(uint8_t sig[CARDANO_SLHDSA_BB6_SIGBYTES],
                            const uint8_t *m, size_t mlen,
                            const uint8_t signkey[CARDANO_SLHDSA_BB6_SIGNKEYBYTES])
{
  const uint8_t *sk = signkey + CARDANO_SLHDSA_BB6_SIGNKEY_SK_OFFSET;
  const unsigned char *sk_prf = sk + SPX_N;
  const unsigned char *pk = sk + 2 * SPX_N;
  spx_ctx ctx;
  unsigned char mhash[SPX_FORS_MSG_BYTES];
  unsigned char root[SPX_N];
  uint32_t i;
  uint64_t tree;
  uint32_t idx_leaf;
  uint32_t wots_addr[8] = {0};
  uint32_t tree_addr[8] = {0};

  memcpy(ctx.sk_seed, sk, SPX_N);
  memcpy(ctx.pub_seed, pk, SPX_N);
  initialize_hash_function(&ctx);

  set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
  set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

  gen_message_random(sig, sk_prf, pk /* opt_rand = PK.seed */, m, mlen, &ctx);
  hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
  sig += SPX_N;

  set_tree_addr(wots_addr, tree);
  set_keypair_addr(wots_addr, idx_leaf);

  fors_sign(sig, root, mhash, &ctx, wots_addr);
  sig += SPX_FORS_BYTES;

  for (i = 0; i < SPX_D; i++) {
    set_layer_addr(tree_addr, i);
    set_tree_addr(tree_addr, tree);
    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, idx_leaf);
    merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
    sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
    tree = tree >> SPX_TREE_HEIGHT;
  }
  return 0;
}

/* Reference crypto_sign_verify, fixed signature length. */
int cardano_slhdsa_bb6_verify(const uint8_t sig[CARDANO_SLHDSA_BB6_SIGBYTES],
                              const uint8_t *m, size_t mlen,
                              const uint8_t pk[CARDANO_SLHDSA_BB6_PUBLICKEYBYTES])
{
  spx_ctx ctx;
  const unsigned char *pub_root = pk + SPX_N;
  unsigned char mhash[SPX_FORS_MSG_BYTES];
  unsigned char wots_pk[SPX_WOTS_BYTES];
  unsigned char root[SPX_N];
  unsigned char leaf[SPX_N];
  unsigned int i;
  uint64_t tree;
  uint32_t idx_leaf;
  uint32_t wots_addr[8] = {0};
  uint32_t tree_addr[8] = {0};
  uint32_t wots_pk_addr[8] = {0};

  memcpy(ctx.pub_seed, pk, SPX_N);
  initialize_hash_function(&ctx);

  set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
  set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
  set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

  hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
  sig += SPX_N;

  set_tree_addr(wots_addr, tree);
  set_keypair_addr(wots_addr, idx_leaf);

  fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
  sig += SPX_FORS_BYTES;

  for (i = 0; i < SPX_D; i++) {
    set_layer_addr(tree_addr, i);
    set_tree_addr(tree_addr, tree);
    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, idx_leaf);
    copy_keypair_addr(wots_pk_addr, wots_addr);
    wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
    sig += SPX_WOTS_BYTES;
    thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);
    compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT, &ctx, tree_addr);
    sig += SPX_TREE_HEIGHT * SPX_N;
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
    tree = tree >> SPX_TREE_HEIGHT;
  }

  if (memcmp(root, pub_root, SPX_N)) return -1;
  return 0;
}
