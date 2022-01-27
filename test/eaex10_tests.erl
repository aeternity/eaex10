-module(eaex10_tests).
-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

-import(eaex10, [encode_base58c/1, decode_base58c/1]).

bip32_master_test() ->
  Test = fun({Seed, _DerivationPath, ExtPub, ExtPriv}) ->
             DKey      = eaex10:master_key(secp256k1, hex_to_bin(Seed)),
             DKeyPub   = eaex10:private_to_public(DKey),
             Bip32Priv = eaex10:enc_bip32_key(DKey),
             Bip32Pub  = eaex10:enc_bip32_key(public, DKeyPub),
             ?assertEqual(ExtPriv, encode_base58c(Bip32Priv)),
             ?assertEqual(ExtPub, encode_base58c(Bip32Pub))
         end,
  [ Test(V) || V = {_, "m", _, _} <- test_vectors_bib32() ].

bip32_derivation_ok_test() ->
  Test = fun({Seed, DerivationPath, ExtPub, ExtPriv}) ->
             ?debugFmt("Test derive: ~s", [DerivationPath]),
             DKey      = eaex10:derive_path_from_seed(secp256k1, DerivationPath, hex_to_bin(Seed)),
             DKeyPub   = eaex10:private_to_public(DKey),
             Bip32Priv = eaex10:enc_bip32_key(DKey),
             Bip32Pub  = eaex10:enc_bip32_key(public, DKeyPub),
             ?assertEqual(ExtPriv, encode_base58c(Bip32Priv)),
             ?assertEqual(ExtPub, encode_base58c(Bip32Pub))
         end,
  [ Test(V) || V <- test_vectors_bib32() ].

slip10_derivation_ok_test() ->
  Test = fun({Type, Seed, DerivationPath, FP, CC, Priv, Pub}) ->
             ?debugFmt("Test derive: ~s", [DerivationPath]),
             DKey = eaex10:derive_path_from_seed(Type, DerivationPath, hex_to_bin(Seed)),
             DKeyPub = eaex10:private_to_public(DKey),
%%              Bip32Priv = eaex10:enc_bip32_key(DKey),
%%              Bip32Pub  = eaex10:enc_bip32_key(DKeyPub),
%%              ?assertEqual(ExtPriv, encode_base58c(Bip32Priv)),
%%              ?assertEqual(ExtPub, encode_base58c(Bip32Pub))
            PrivBin = hex_to_bin(Priv),
            ?assertEqual(hex_to_bin(CC), maps:get(chain_code, DKey)),
            ?assertEqual(hex_to_bin(FP), maps:get(fprint, DKey)),
            ?assertEqual(<<PrivBin/bytes>>, maps:get(priv_key, DKey)),
            <<0:8, BinPub/binary>> = hex_to_bin(Pub),
            ?assertEqual(BinPub, maps:get(pub_key, DKeyPub))
         end,
  [ Test(V) || V <- test_vectors_slip10() ].

aeax10_slip10_derivation_ok_test() ->
  Test = fun({Type, Seed, DerivationPath, FP, CC, Priv, Pub}) ->
             ?debugFmt("Test derive: ~s", [DerivationPath]),
             DKey = eaex10:derive_path_from_seed(Type, DerivationPath, hex_to_bin(Seed)),
             DKeyPub = eaex10:private_to_public(DKey),
             PrivBin = hex_to_bin(Priv),
             ?assertEqual(hex_to_bin(CC), maps:get(chain_code, DKey)),
             ?assertEqual(hex_to_bin(FP), maps:get(fprint, DKey)),
             ?assertEqual(<<PrivBin/bytes>>, maps:get(priv_key, DKey)),
             ?assertEqual(hex_to_bin(Pub), maps:get(pub_key, DKeyPub))
         end,
  [ Test(V) || V <- test_vectors_aex10_slip10() ].

aeax10_derivation_ok_test() ->
  Test = fun({Seed, {AcIx, AdIx}, FP, CC, Priv, Pub}) ->
             ?debugFmt("Test derive: account ~p address: ~p", [AcIx, AdIx]),
             DKey = eaex10:derive_aex10_from_seed(hex_to_bin(Seed), AcIx, AdIx),
             DKeyPub = eaex10:private_to_public(DKey),
             PrivBin = hex_to_bin(Priv),
             ?assertEqual(hex_to_bin(CC), maps:get(chain_code, DKey)),
             ?assertEqual(hex_to_bin(FP), maps:get(fprint, DKey)),
             ?assertEqual(<<PrivBin/bytes>>, maps:get(priv_key, DKey)),
             ?assertEqual(hex_to_bin(Pub), maps:get(pub_key, DKeyPub))
         end,
  [ Test(V) || V <- test_vectors_aex10() ].

%% Test vectors for BIP0032: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
test_vectors_bib32() ->
  [ %% {Seed, derivation, extended pub, extended priv}
   { "000102030405060708090a0b0c0d0e0f",
     "m",
     <<"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8">>,
     <<"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi">>
   },
   { "000102030405060708090a0b0c0d0e0f",
     "m/0H",
     <<"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw">>,
     <<"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7">>
   },
   { "000102030405060708090a0b0c0d0e0f",
     "m/0H/1",
     <<"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ">>,
     <<"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs">>
   },
   { "000102030405060708090a0b0c0d0e0f",
     "m/0H/1/2H",
     <<"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5">>,
     <<"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM">>
   },
   { "000102030405060708090a0b0c0d0e0f",
     "m/0H/1/2H/2",
     <<"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV">>,
     <<"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334">>
   },
   { "000102030405060708090a0b0c0d0e0f",
     "m/0H/1/2H/2/1000000000",
     <<"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy">>,
     <<"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76">>
   },

   { "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
     "m",
     <<"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB">>,
     <<"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U">>
   },
   { "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
     "m/0",
     <<"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH">>,
     <<"xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt">>
   },
   { "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
     "m/0/2147483647H",
     <<"xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a">>,
     <<"xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9">>
   },
   { "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
     "m/0/2147483647H/1",
     <<"xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon">>,
     <<"xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef">>
   },
   { "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
     "m/0/2147483647H/1/2147483646H",
     <<"xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL">>,
     <<"xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc">>
   },
   { "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
     "m/0/2147483647H/1/2147483646H/2",
     <<"xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt">>,
     <<"xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j">>
   },

   { "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
     "m",
     <<"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13">>,
     <<"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6">>
   },
   { "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
     "m/0H",
     <<"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y">>,
     <<"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L">>
   },

   { "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
     "m",
     <<"xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa">>,
     <<"xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv">>
   },
   { "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
     "m/0H",
     <<"xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m">>,
     <<"xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G">>
   },
   { "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
     "m/0H/1H",
     <<"xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt">>,
     <<"xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1">>
   }].

%% Test vectors from SLIP0010: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
test_vectors_slip10() ->
  [{ ed25519,
     "000102030405060708090a0b0c0d0e0f",
     "m",
     "00000000",
     "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
     "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
     "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"},
   { ed25519,
     "000102030405060708090a0b0c0d0e0f",
     "m/0H",
     "ddebc675",
     "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
     "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
     "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"},
   { ed25519,
     "000102030405060708090a0b0c0d0e0f",
     "m/0H/1H",
     "13dab143",
     "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
     "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
     "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"},
   { ed25519,
     "000102030405060708090a0b0c0d0e0f",
     "m/0H/1H/2H",
     "ebe4cb29",
     "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
     "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
     "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"},
   { ed25519,
     "000102030405060708090a0b0c0d0e0f",
     "m/0H/1H/2H/2H",
     "316ec1c6",
     "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
     "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
     "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"},
   { ed25519,
     "000102030405060708090a0b0c0d0e0f",
     "m/0H/1H/2H/2H/1000000000H",
     "d6322ccd",
     "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
     "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
     "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"}
  ].

%% NOTE: SLIP0010 is fuzzy about public key format, they prepend the ed25519
%% public key with a 0x00 byte. This affects the fingerprint(s). Here we
%% omit the 0-byte, but add it when computing fingerprints.
test_vectors_aex10_slip10() ->
  [ { ed25519,
      "000102030405060708090a0b0c0d0e0f",
      "m/44H/457H/0H/0H/0H",
      "0AC70E0D",
      "55DABD8682B4ED808AD21AF8798B34905EE8E1A0057F15DC151A8487CFAB630F",
      "624357924DABE9460677F574853CBE017B5506E53F41EC0179AFCA9519957925",
      "9A3D5001D37C85E72A953B1C0EB7C5BC8B5FBD4640AA4D488FA029CD526F206B"},
    { ed25519,
      "000102030405060708090a0b0c0d0e0f",
      "m/44H/457H/0H/0H/17H",
      "0AC70E0D",
      "98CAA03190E8F23CE5362ED3F3EAFCB4FB9A08B9E9329DC168BCB3EF563283BF",
      "E2ED1D3BC80DB4644D5D855E60791E72C2E98AA69ED4D024C659FF642D8F6B77",
      "833A6227139952868E49BBBDAAB17852C002B1651CC8A633F623A554A59A00FE"},
    { ed25519,
      "000102030405060708090a0b0c0d0e0f",
      "m/44H/457H/0H/0H/921H",
      "0AC70E0D",
      "BF9F7535FDD146027D732D4BB1FCE9309CF1561DFDDA6ACD68C399BBFB09828D",
      "00D113B53996EB8E0EC52FD41FD8EFE5E6719519106FED54416A3243DC603C7E",
      "9DEE1871C20AEF56672B1BAA9C521FABEDA048B0612330E92C9A1B967A4732D6"},
    { ed25519,
      "000102030405060708090a0b0c0d0e0f",
      "m/44H/457H/42H/0H/0H",
      "FB2212CF",
      "B2102A2258CB55AB3A4E20241D373AEEC92803666A4DDCED158B22406B6726BA",
      "F54EA1206A4DD02D4DC59EFFDBD89A7524E5BD719D3CCAC2F28F3CFA8D6A24C2",
      "5331419AA320C8DED7AD86DD63935692D384C4A82A0D83EDAC8093FAEB36BF2E"},
    { ed25519,
      "000102030405060708090a0b0c0d0e0f",
      "m/44H/457H/42H/0H/17H",
      "FB2212CF",
      "6F90E396148F2D769CC4791E41B3107EF530302D682CE52D3945BCCF5CFFA324",
      "5CBD84C82F04F791C5B262C933602456EA9BCDB74B2E738F7A06BF5A72598A34",
      "FD4F4FB851911073D6E1A0F7255A68C4A189824724DAB27A6260E6DEF3762A11"},
    { ed25519,
      "000102030405060708090a0b0c0d0e0f",
      "m/44H/457H/42H/0H/921H",
      "FB2212CF",
      "BABF55A4CA273CB0F889FB593AC5877E5B0C78EC645A17E193FE396B28306499",
      "C28EDF7DB1D3093D2254945E162E10CD3AB3D6862BEC9514C090DF5228ADB478",
      "44C3488A82A8D75EBF386E3027A7FA74F8102889E22B01951BE1022D2208ECE9"},
    { ed25519,
      "000102030405060708090a0b0c0d0e0f",
      "m/44H/457H/123H/0H/0H",
      "CADEACEF",
      "805C6C28D3FBB45E52D5CB37EDAE805EAF57CA408E79145B2E5F7861FA0A740F",
      "D399B502D691A0E07FD8B336C354BC5D5703B2B0DEC2D9894689E5810B88C47C",
      "8AB44B79F131B3F7CC9A19BFCFB0D7794720A1A9CAE9350DCCDD6702A1900E0D"},
    { ed25519,
      "000102030405060708090a0b0c0d0e0f",
      "m/44H/457H/123H/0H/17H",
      "CADEACEF",
      "F09AB6EEDD59084D9DAF915B32AC761F290DACC857BC64CC2613D139B2211081",
      "EEA0D75662F803629108A526EF0A69E3B5FB18CBE33A8E0CF0406D5617C82B23",
      "A53F0BEC67A82825C49C2A55DE3C56F0614D1581CA3B1452B2BFCB08E2DD6DCC"},
    { ed25519,
      "000102030405060708090a0b0c0d0e0f",
      "m/44H/457H/123H/0H/921H",
      "CADEACEF",
      "D27BB9AF44305B765AF39AE8A1D093C9B68331DCE961E71BD77807359C6ABF8C",
      "CA2298DC98D85E553833453806FEAE6918B2F672C7C1D6775A5F4C1B61332102",
      "3AC0548036589278CAD9000691D4589FF8CF5A687C27B3ACD2B6BC75D1FB518E"}
  ].

%% NOTE: SLIP0010 is fuzzy about public key format, they prepend the ed25519
%% public key with a 0x00 byte. This affects the fingerprint(s). Here we
%% omit the 0-byte, but add it when computing fingerprints.
test_vectors_aex10() ->
  [ { "000102030405060708090a0b0c0d0e0f",
      {0, 0},
      "0AC70E0D",
      "55DABD8682B4ED808AD21AF8798B34905EE8E1A0057F15DC151A8487CFAB630F",
      "624357924DABE9460677F574853CBE017B5506E53F41EC0179AFCA9519957925",
      "9A3D5001D37C85E72A953B1C0EB7C5BC8B5FBD4640AA4D488FA029CD526F206B"},
    { "000102030405060708090a0b0c0d0e0f",
      {0, 17},
      "0AC70E0D",
      "98CAA03190E8F23CE5362ED3F3EAFCB4FB9A08B9E9329DC168BCB3EF563283BF",
      "E2ED1D3BC80DB4644D5D855E60791E72C2E98AA69ED4D024C659FF642D8F6B77",
      "833A6227139952868E49BBBDAAB17852C002B1651CC8A633F623A554A59A00FE"},
    { "000102030405060708090a0b0c0d0e0f",
      {0, 921},
      "0AC70E0D",
      "BF9F7535FDD146027D732D4BB1FCE9309CF1561DFDDA6ACD68C399BBFB09828D",
      "00D113B53996EB8E0EC52FD41FD8EFE5E6719519106FED54416A3243DC603C7E",
      "9DEE1871C20AEF56672B1BAA9C521FABEDA048B0612330E92C9A1B967A4732D6"},
    { "000102030405060708090a0b0c0d0e0f",
      {42, 0},
      "FB2212CF",
      "B2102A2258CB55AB3A4E20241D373AEEC92803666A4DDCED158B22406B6726BA",
      "F54EA1206A4DD02D4DC59EFFDBD89A7524E5BD719D3CCAC2F28F3CFA8D6A24C2",
      "5331419AA320C8DED7AD86DD63935692D384C4A82A0D83EDAC8093FAEB36BF2E"},
    { "000102030405060708090a0b0c0d0e0f",
      {42, 17},
      "FB2212CF",
      "6F90E396148F2D769CC4791E41B3107EF530302D682CE52D3945BCCF5CFFA324",
      "5CBD84C82F04F791C5B262C933602456EA9BCDB74B2E738F7A06BF5A72598A34",
      "FD4F4FB851911073D6E1A0F7255A68C4A189824724DAB27A6260E6DEF3762A11"},
    { "000102030405060708090a0b0c0d0e0f",
      {42, 921},
      "FB2212CF",
      "BABF55A4CA273CB0F889FB593AC5877E5B0C78EC645A17E193FE396B28306499",
      "C28EDF7DB1D3093D2254945E162E10CD3AB3D6862BEC9514C090DF5228ADB478",
      "44C3488A82A8D75EBF386E3027A7FA74F8102889E22B01951BE1022D2208ECE9"},
    { "000102030405060708090a0b0c0d0e0f",
      {123, 0},
      "CADEACEF",
      "805C6C28D3FBB45E52D5CB37EDAE805EAF57CA408E79145B2E5F7861FA0A740F",
      "D399B502D691A0E07FD8B336C354BC5D5703B2B0DEC2D9894689E5810B88C47C",
      "8AB44B79F131B3F7CC9A19BFCFB0D7794720A1A9CAE9350DCCDD6702A1900E0D"},
    { "000102030405060708090a0b0c0d0e0f",
      {123, 17},
      "CADEACEF",
      "F09AB6EEDD59084D9DAF915B32AC761F290DACC857BC64CC2613D139B2211081",
      "EEA0D75662F803629108A526EF0A69E3B5FB18CBE33A8E0CF0406D5617C82B23",
      "A53F0BEC67A82825C49C2A55DE3C56F0614D1581CA3B1452B2BFCB08E2DD6DCC"},
    { "000102030405060708090a0b0c0d0e0f",
      {123, 921},
      "CADEACEF",
      "D27BB9AF44305B765AF39AE8A1D093C9B68331DCE961E71BD77807359C6ABF8C",
      "CA2298DC98D85E553833453806FEAE6918B2F672C7C1D6775A5F4C1B61332102",
      "3AC0548036589278CAD9000691D4589FF8CF5A687C27B3ACD2B6BC75D1FB518E"}
  ].

%% mk_aex_test_vectors_test() ->
%%   BasePath = "m/44H/457H/",
%%   Seed = "000102030405060708090a0b0c0d0e0f",
%%   AccountIxs = ["0H", "42H", "123H"],
%%   AddressIxs = ["0H", "17H", "921H"],
%%   ?debugFmt("", []),
%%   ?debugFmt("Test vector(s) for AEX-10", []),
%%   ?debugFmt("", []),
%%   ?debugFmt("Seed (hex): ~s", [Seed]),
%%   Derive = fun(AcIx, AdIx) ->
%%       Path = BasePath ++ AcIx ++ "/0H/" ++ AdIx,
%%       DKey = eaex10:private_to_public(eaex10:derive_path_from_seed(ed25519, Path, hex_to_bin(Seed))),
%%       ?debugFmt("  Chain: ~s", [Path]),
%%       ?debugFmt("    - Fingerprint: ~s", [bin_to_hex(maps:get(fprint, DKey))]),
%%       ?debugFmt("    - Chain code:  ~s", [bin_to_hex(maps:get(chain_code, DKey))]),
%%       ?debugFmt("    - Private:     ~s", [bin_to_hex(maps:get(priv_key, DKey))]),
%%       ?debugFmt("    - Public:      ~s", [bin_to_hex(maps:get(pub_key, DKey))])
%%       ?debugFmt("\n{ ed25519,\n  \"~s\",\n  \"~s\",\n  \"~s\",\n  \"~s\",\n  \"~s\",\n  \"~s\"},",
%%         [Seed, Path, bin_to_hex(maps:get(fprint, DKey)), bin_to_hex(maps:get(chain_code, DKey)),
%%          bin_to_hex(maps:get(priv_key, DKey)), bin_to_hex(maps:get(pub_key, DKey))])
%%     end,
%%   [ Derive(A, B) || A <- AccountIxs, B <- AddressIxs ].

-spec hex_to_bin(Input :: string()) -> binary().
hex_to_bin(S) ->
  hex_to_bin(S, []).
hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hex_to_bin(T, [V | Acc]).

-spec bin_to_hex(Input :: binary()) -> string().
bin_to_hex(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]).
