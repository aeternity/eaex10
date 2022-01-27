-module(eaex10).

-export([master_key/2,
         derive_aex10_from_seed/3, derive_aex10_from_seed/4,
         derive_aex10_from_masterkey/3, derive_aex10_from_masterkey/4,
         derive_path_from_seed/3,
         derive_path/2,
         private_key/1, public_key/1,
         enc_bip32_key/1, enc_bip32_key/2,
         dec_bip32_key/1,
         encode_base58c/1, decode_base58c/1,
         private_to_public/1]).

-define(SECP256K1_SEED, <<"Bitcoin seed">>).
-define(ED25519_SEED,   <<"ed25519 seed">>).
%% -define(NIST256P1_SEED, <<"Nist256p1 seed">>).

-define(SECP256K1_ORDER, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).
-define(ED25519_ORDER, 16#1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED).
%% -define(NIST256P1_ORDER, 16#FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551).

-define(PRIVATE_KEY_TYPE, 0).
-define(HARD_OFFSET, 16#7FFFFFFF).

-type curve() :: ed25519 | secp256k1.

-type binary_32() :: <<_:256>>.

-type derived_key() ::
  #{ curve      := curve(),
     depth      := non_neg_integer(),
     child      := non_neg_integer(),
     fprint     := <<_:32>>,
     priv_key   := binary_32(),
     pub_key    := undefined | binary_32() | <<_:264>>,
     chain_code := binary_32() }.

-spec private_key(DKey :: derived_key()) -> {ok, binary_32()} | no_private_key.
private_key(#{priv_key := undefined}) ->
  no_private_key;
private_key(#{priv_key := PrivKey}) ->
  {ok, PrivKey}.

-spec public_key(DKey :: derived_key()) -> {ok, binary_32()}.
public_key(DKey = #{pub_key := undefined}) ->
  public_key(private_to_public(DKey));
public_key(#{priv_key := PrivKey}) ->
  {ok, PrivKey}.

-spec private_to_public(DKey :: derived_key()) -> derived_key().
private_to_public(DKey = #{curve := Curve, pub_key := undefined,
                           priv_key := <<PrivateKey:32/binary>>}) ->
  DKey#{pub_key := private_to_public(Curve, PrivateKey)};
private_to_public(DKey) ->
  DKey. %% Public key field is already populated

-spec master_key(Curve :: curve(), Seed :: binary()) -> derived_key().
master_key(Curve, Seed) when byte_size(Seed) >= 16, byte_size(Seed) =< 64 ->
  I = <<ILeft:256, IRight:32/bytes>> = epbkdf2:hmac(sha512, curve_key(Curve), Seed),

  case Curve /= ed25519 andalso (ILeft == 0 orelse ILeft > curve_order(Curve)) of
    true  -> master_key(Curve, I);
    false -> #{curve => Curve, depth => 0, fprint => <<0:32>>, child => 0,
               priv_key => <<ILeft:256>>, pub_key => undefined, chain_code => IRight}
  end.

-spec derive_aex10_from_seed(Seed         :: binary(),
                             AccountIndex :: non_neg_integer(),
                             AddressIndex :: non_neg_integer()) -> derived_key().
derive_aex10_from_seed(Seed, AccountIndex, AddressIndex) ->
  derive_aex10_from_seed(Seed, AccountIndex, 0, AddressIndex).

-spec derive_aex10_from_seed(Seed         :: binary(),
                             AccountIndex :: non_neg_integer(),
                             Change       :: non_neg_integer(),
                             AddressIndex :: non_neg_integer()) -> derived_key().
derive_aex10_from_seed(Seed, AccountIndex, Change, AddressIndex) ->
  Path = "m/44H/457H/" ++ integer_to_list(AccountIndex) ++ "H/" ++
    integer_to_list(Change) ++ "H/" ++ integer_to_list(AddressIndex) ++ "H",
  derive_path_from_seed(ed25519, Path, Seed).

-spec derive_aex10_from_masterkey(MasterKey    :: derived_key(),
                                  AccountIndex :: non_neg_integer(),
                                  AddressIndex :: non_neg_integer()) -> derived_key().
derive_aex10_from_masterkey(MasterKey, AccountIndex, AddressIndex) ->
  derive_aex10_from_masterkey(MasterKey, AccountIndex, 0, AddressIndex).

-spec derive_aex10_from_masterkey(MasterKey    :: binary(),
                                  AccountIndex :: non_neg_integer(),
                                  Change       :: non_neg_integer(),
                                  AddressIndex :: non_neg_integer()) -> derived_key().
derive_aex10_from_masterkey(MasterKey, AccountIndex, Change, AddressIndex) ->
  Path = "m/44H/457H/" ++ integer_to_list(AccountIndex) ++ "H/" ++
    integer_to_list(Change) ++ "H/" ++ integer_to_list(AddressIndex) ++ "H",
  derive_path(Path, MasterKey).

-spec derive_path_from_seed(Curve :: curve(),
                            Path  :: string(),
                            Seed  :: binary()) -> derived_key().
derive_path_from_seed(Curve, Path, Seed) ->
  DKey = master_key(Curve, Seed),
  derive_path(Path, DKey).

-spec derive_path(Path  :: string(),
                  DKey0 :: derived_key()) -> derived_key().
derive_path(Path, DKey0) ->
  case {Path, key_type(DKey0)} of
    {"m" ++ Path1, private} ->
      derive_private_path(Path1, DKey0);
    {"m" ++ _Path1, public} ->
      error({invalid_derivation, "Can't derive private keys from a public key"});
    {"M" ++ Path1, private} ->
      DKey1 = derive_private_path(Path1, DKey0),
      private_to_public(DKey1);
    {"M" ++ Path1, public} ->
      derive_public_path(Path1, DKey0);
    _ ->
      error({invalid_path, "Expecting path to start with 'm/' or 'M/'"})
  end.

%% BIP32 Extended keys
-define(BITCOIN_MAIN_PRIV, <<16#0488ADE4:32>>).
-define(BITCOIN_MAIN_PUB,  <<16#0488B21E:32>>).

-spec enc_bip32_key(DKey :: derived_key()) -> binary().
enc_bip32_key(DKey) ->
  enc_bip32_key(key_type(DKey), DKey).

-spec enc_bip32_key(KeyType :: private | public, DKey :: derived_key()) -> binary().
enc_bip32_key(KeyType, DKey) ->
  #{chain_code := <<ChainCode:32/bytes>>, depth := Depth,
    fprint := <<FPrint:4/bytes>>, child := Child, curve := Curve} = DKey,

  VsnBytes = version_bytes(Curve, KeyType),
  Key = case {KeyType, DKey} of
          {public, #{pub_key := <<PubKey:33/bytes>>}}    -> PubKey;
          {private, #{priv_key := <<PrivKey:32/bytes>>}} -> <<0:8, PrivKey/bytes>>
        end,

  <<VsnBytes:4/bytes, Depth:8, FPrint:4/bytes,
    Child:32, ChainCode:32/bytes, Key:33/bytes>>.

-spec dec_bip32_key(Bip32Key :: binary()) -> derived_key().
dec_bip32_key(<<VsnBytes:4/bytes, Depth:8, FPrint:4/bytes,
                Child:32, ChainCode:32/bytes, Key:33/bytes>>) ->
  {Curve, KeyType} =
    case VsnBytes of
      ?BITCOIN_MAIN_PUB  -> {secp256k1, public};
      ?BITCOIN_MAIN_PRIV -> {secp256k1, private}
    end,
  DKey = #{priv_key => undefined, pub_key => undefined, chain_code => ChainCode,
           depth => Depth, fprint => FPrint, child => Child, curve => Curve},
  case KeyType of
    private ->
      <<_:8, PrivKey:32/bytes>> = Key,
      DKey#{priv_key := PrivKey};
    public ->
      DKey#{pub_key := Key}
  end.

-spec encode_base58c(Bin :: binary()) -> binary().
encode_base58c(Bin) ->
  C = check_str(Bin),
  binary_to_base58(iolist_to_binary([Bin, C])).

-spec decode_base58c(Bin :: binary()) -> binary().
decode_base58c(Bin) ->
  DecodedBin = base58_to_binary(Bin),
  Sz = byte_size(DecodedBin),
  BSz = Sz - 4,
  <<Body:BSz/binary, C:4/binary>> = DecodedBin,
  C = check_str(Body),
  Body.

%% --- Internal functions

private_to_public(secp256k1, PrivateKey) ->
  ecu_ecdsa:private_to_public(secp256k1, PrivateKey);
private_to_public(ed25519, PrivateKey) ->
  #{public := PublicKey} = ecu_eddsa:sign_seed_keypair(PrivateKey),
  PublicKey.

curve_key(secp256k1) -> ?SECP256K1_SEED;
curve_key(ed25519)   -> ?ED25519_SEED.
%% curve_key(nist256p1) -> ?NIST256P1_SEED.

curve_order(secp256k1) -> ?SECP256K1_ORDER;
curve_order(ed25519)   -> ?ED25519_ORDER.
%% curve_order(nist256p1) -> ?NIST256P1_ORDER.

version_bytes(secp256k1, private) -> ?BITCOIN_MAIN_PRIV;
version_bytes(secp256k1, public)  -> ?BITCOIN_MAIN_PUB.

parse_segment(Segment) ->
  case lists:reverse(Segment) of
    "H" ++ S -> {hard, list_to_integer(lists:reverse(S))};
    _        -> {normal, list_to_integer(Segment)}
  end.

key_type(#{priv_key := <<_/bytes>>})                    -> private;
key_type(#{pub_key := PubKey}) when PubKey /= undefined -> public.

binary_to_base58(Bin) ->
    iolist_to_binary(base58:binary_to_base58(Bin)).

base58_to_binary(Bin) when is_binary(Bin) ->
    base58:base58_to_binary(binary_to_list(Bin)).

check_str(Bin) ->
    <<C:32/bitstring,_/binary>> =
        sha256_hash(sha256_hash(Bin)),
    C.

sha256_hash(Bin) -> crypto:hash(sha256, Bin).

derive_private_path(Path, DKey) ->
  Segments = lists:map(fun parse_segment/1, string:lexemes(Path, "/")),
  lists:foldl(fun derive_private_path_segment/2, DKey, Segments).

derive_private_path_segment(Ix, DKey = #{curve := Curve}) ->
  derive_private_path_segment(Curve, Ix, DKey).

derive_private_path_segment(secp256k1, {hard, Ix0}, DKey = #{priv_key := PKey, chain_code := CC}) ->
  Ix = Ix0 + ?HARD_OFFSET + 1,
  Data = <<0:8, PKey:32/bytes, Ix:32>>,
  case derive_secp256k1_private_path_segment_(Ix, CC, Data, DKey) of
    {error, _}  -> derive_private_path_segment({hard, Ix0 + 1}, DKey);
    {ok, DKey1} -> DKey1
  end;
derive_private_path_segment(secp256k1, {normal, Ix}, DKey = #{priv_key := PrivKey, chain_code := CC}) ->
  SerPt = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(PrivKey)),
  Data  = <<SerPt:33/bytes, Ix:32>>,
  case derive_secp256k1_private_path_segment_(Ix, CC, Data, DKey) of
    {error, _}  -> derive_private_path_segment({normal, Ix + 1}, DKey);
    {ok, DKey1} -> DKey1
  end;
derive_private_path_segment(ed25519, {normal, _Ix}, _DKey) ->
  error({invalid_derivation, "Can't derive normal path for ed25519"});
derive_private_path_segment(ed25519, {hard, Ix0}, DKey = #{priv_key := Key, chain_code := CC}) ->
  Ix = Ix0 + ?HARD_OFFSET + 1,
  Data = <<0:8, Key:32/bytes, Ix:32>>,
  <<ILeft:256, IRight:32/bytes>> = epbkdf2:hmac(sha512, CC, Data),
  DKey#{priv_key := <<ILeft:256>>, pub_key := undefined, chain_code := IRight,
        depth := maps:get(depth, DKey) + 1, child := Ix,
        fprint := fingerprint(DKey)}.

derive_secp256k1_private_path_segment_(Ix, Key, Data, DKey = #{priv_key := <<PKey:256>>}) ->
  <<ILeft:256, IRight:32/bytes>> = epbkdf2:hmac(sha512, Key, Data),
  case ILeft >= ?SECP256K1_ORDER of
    true  -> {error, bad_derivation};
    false ->
      KeyI = (ILeft + PKey) rem ?SECP256K1_ORDER,
      case KeyI == 0 of
        true  -> {error, bad_derivation};
        false ->
          {ok, DKey#{priv_key := <<KeyI:256>>, pub_key := undefined, chain_code := IRight,
                     depth := maps:get(depth, DKey) + 1, child := Ix,
                     fprint := fingerprint(DKey)}}
      end
  end.

derive_public_path(Path, DKey) ->
  Segments = lists:map(fun parse_segment/1, string:lexemes(Path, "/")),
  lists:foldl(fun derive_public_path_segment/2, DKey, Segments).

derive_public_path_segment(Ix, DKey = #{curve := Curve}) ->
  derive_public_path_segment(Curve, Ix, DKey).

derive_public_path_segment(_, {hard, _}, _DKey) ->
  error({invalid_derivation, "Can't derive hardened path from public key"});
derive_public_path_segment(secp256k1, {normal, Ix},
                           DKey = #{pub_key := ParKey, chain_code := CC}) ->
  Data = <<ParKey:33/bytes, Ix:32>>,
  <<ILeft:256, IRight:32/bytes>> = epbkdf2:hmac(sha512, CC, Data),
  case ILeft >= ?SECP256K1_ORDER of
    true -> derive_public_path_segment({normal, Ix + 1}, DKey);
    false ->
      KeyPt = esecp256k1:add_p(esecp256k1:scalar_mul_base(ILeft),
                               esecp256k1:decompress(ParKey)),
      case KeyPt of
        {0, 0} -> derive_public_path_segment({normal, Ix + 1}, DKey);
        _ ->
          DKey#{pub_key := esecp256k1:compress(KeyPt), chain_code := IRight,
                priv_key := undefined, depth := maps:get(depth, DKey) + 1,
                child := Ix, fprint := fingerprint(DKey)}
      end
  end;
derive_public_path_segment(ed25519, _, _) ->
  error({invalid_derivation, "Public derivation for ed25519 not supported"}).

fingerprint(DKey = #{pub_key := undefined}) ->
  fingerprint(private_to_public(DKey));
fingerprint(#{curve := secp256k1, pub_key := PubKey}) ->
  <<FP:4/bytes, _/bytes>> = crypto:hash(ripemd160, crypto:hash(sha256, PubKey)),
  FP;
fingerprint(#{curve := ed25519, pub_key := PubKey}) ->
  %% https://github.com/satoshilabs/slips/issues/1251
  %% An extra 0-byte is inserted first for some reason.
  <<FP:4/bytes, _/bytes>> = crypto:hash(ripemd160, crypto:hash(sha256, <<0:8, PubKey/binary>>)),
  FP.


