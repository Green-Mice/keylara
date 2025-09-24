%%%===================================================================
%%% Description: Dilithium (CRYSTALS-Dilithium) post-quantum signature scheme
%%% Based on NIST FIPS 204 (draft) with Alara entropy integration
%%%===================================================================
-module(keylara_dilithium).
-export([
    generate_keypair/2,
    sign/3,
    verify/4,
    validate_public_key/2,
    validate_private_key/2,
    validate_signature/2,
    get_parameter_sizes/1
]).

-include("keylara.hrl").

-define(DILITHIUM_2, dilithium_2).
-define(DILITHIUM_3, dilithium_3).
-define(DILITHIUM_5, dilithium_5).

-define(DILITHIUM_SEED_SIZE, 32).
-define(DILITHIUM_Q, 8380417).
-define(DILITHIUM_N, 256).

-define(DILITHIUM_PARAMS, #{
    dilithium_2 => #{
        k => 4,
        l => 4,
        eta => 2,
        tau => 39,
        beta => 78,
        gamma_1 => (1 bsl 17) - 1,
        gamma_2 => (1 bsl 19) - 1,
        public_key_size => 1312,
        private_key_size => 2528,
        signature_size => 2420,
        crh_bytes => 48,
        z_bytes => 108,
        seed_size => 32,
        kappa => 32
    },
    dilithium_3 => #{
        k => 6,
        l => 5,
        eta => 4,
        tau => 49,
        beta => 196,
        gamma_1 => (1 bsl 19) - 1,
        gamma_2 => (1 bsl 19) - 1,
        public_key_size => 1952,
        private_key_size => 4032,
        signature_size => 3293,
        crh_bytes => 64,
        z_bytes => 147,
        seed_size => 32,
        kappa => 48
    },
    dilithium_5 => #{
        k => 8,
        l => 7,
        eta => 2,
        tau => 60,
        beta => 120,
        gamma_1 => (1 bsl 19) - 1,
        gamma_2 => (1 bsl 19) - 1,
        public_key_size => 2592,
        private_key_size => 4864,
        signature_size => 4595,
        crh_bytes => 64,
        z_bytes => 204,
        seed_size => 32,
        kappa => 64
    }
}).

-type dilithium_param_set() :: dilithium_2 | dilithium_3 | dilithium_5.
-type dilithium_public_key() :: binary().
-type dilithium_private_key() :: binary().
-type dilithium_signature() :: binary().

-spec generate_keypair(pid(), dilithium_param_set()) ->
    {ok, {dilithium_public_key(), dilithium_private_key()}} | keylara_error().
generate_keypair(NetPid, ParamSet) when is_pid(NetPid) ->
    case maps:get(ParamSet, ?DILITHIUM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            try
                case keylara:get_entropy_bytes(NetPid, 2 * ?DILITHIUM_SEED_SIZE) of
                    {ok, Seed} ->
                        {Rho, K} = expand_seed(Seed),
                        {PublicKey, PrivateKey} = dilithium_keygen(Rho, K, Params),
                        {ok, {PublicKey, PrivateKey}};
                    {error, Reason} ->
                        {error, {entropy_generation_failed, Reason}}
                end
            catch
                Class:Reason1:Stacktrace ->
                    {error, {keygen_failed, {Class, Reason1, Stacktrace}}}
            end
    end;
generate_keypair(_, _) ->
    {error, invalid_network_pid}.

-spec sign(binary(), dilithium_private_key(), dilithium_param_set()) ->
    {ok, dilithium_signature()} | keylara_error().
sign(Message, PrivateKey, ParamSet) ->
    case maps:get(ParamSet, ?DILITHIUM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            case validate_private_key(PrivateKey, ParamSet) of
                ok ->
                    try
                        {K, S1, _S2, T0, _PublicKey} = decode_private_key(PrivateKey, Params),
                        Mu = crypto:hash(sha512, <<K/binary, Message/binary>>),
                        Randomness = crypto:strong_rand_bytes(maps:get(crh_bytes, Params)),
                        {Y, Z} = generate_commitment(S1, T0, Mu, Randomness, Params),
                        C = compute_challenge(Message, Y, Mu, Params),
                        {ZPrime, H} = compute_response(C, Z, S1, Params),
                        Signature = encode_signature(C, ZPrime, H, Params),
                        {ok, Signature}
                    catch
                        Class:Reason:Stacktrace ->
                            {error, {signing_failed, {Class, Reason, Stacktrace}}}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

-spec verify(binary(), dilithium_signature(), dilithium_public_key(), dilithium_param_set()) ->
    {ok, boolean()} | keylara_error().
verify(Message, Signature, PublicKey, ParamSet) ->
    case maps:get(ParamSet, ?DILITHIUM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            case validate_public_key(PublicKey, ParamSet) of
                ok ->
                    case validate_signature(Signature, ParamSet) of
                        ok ->
                            try
                                {C, ZPrime, H} = decode_signature(Signature, Params),
                                {Rho, T1} = decode_public_key(PublicKey, Params),
                                Mu = crypto:hash(sha512, <<Rho/binary, Message/binary>>),
                                Y = recompute_Y(C, ZPrime, H, T1, Params),
                                CPrime = compute_challenge(Message, Y, Mu, Params),
                                Valid = constant_time_compare(C, CPrime),
                                {ok, Valid}
                            catch
                                Class:Reason:Stacktrace ->
                                    {error, {verification_failed, {Class, Reason, Stacktrace}}}
                            end;
                        {error, Reason} -> {error, Reason}
                    end;
                {error, Reason} -> {error, Reason}
            end
    end.

-spec validate_public_key(term(), dilithium_param_set()) -> ok | keylara_error().
validate_public_key(PublicKey, ParamSet) when is_binary(PublicKey) ->
    case maps:get(ParamSet, ?DILITHIUM_PARAMS, undefined) of
        undefined -> {error, {invalid_parameter_set, ParamSet}};
        #{public_key_size := ExpectedSize} ->
            case byte_size(PublicKey) of
                ExpectedSize -> ok;
                ActualSize -> {error, {invalid_public_key_size, ActualSize, ExpectedSize}}
            end
    end;
validate_public_key(_, _) -> {error, invalid_public_key_format}.

-spec validate_private_key(term(), dilithium_param_set()) -> ok | keylara_error().
validate_private_key(PrivateKey, ParamSet) when is_binary(PrivateKey) ->
    case maps:get(ParamSet, ?DILITHIUM_PARAMS, undefined) of
        undefined -> {error, {invalid_parameter_set, ParamSet}};
        #{private_key_size := ExpectedSize} ->
            case byte_size(PrivateKey) of
                ExpectedSize -> ok;
                ActualSize -> {error, {invalid_private_key_size, ActualSize, ExpectedSize}}
            end
    end;
validate_private_key(_, _) -> {error, invalid_private_key_format}.

-spec validate_signature(term(), dilithium_param_set()) -> ok | keylara_error().
validate_signature(Signature, ParamSet) when is_binary(Signature) ->
    case maps:get(ParamSet, ?DILITHIUM_PARAMS, undefined) of
        undefined -> {error, {invalid_parameter_set, ParamSet}};
        #{signature_size := ExpectedSize} ->
            case byte_size(Signature) of
                ExpectedSize -> ok;
                ActualSize -> {error, {invalid_signature_size, ActualSize, ExpectedSize}}
            end
    end;
validate_signature(_, _) -> {error, invalid_signature_format}.

-spec get_parameter_sizes(dilithium_param_set()) -> {ok, #{atom() => non_neg_integer()}} | keylara_error().
get_parameter_sizes(ParamSet) ->
    case maps:get(ParamSet, ?DILITHIUM_PARAMS, undefined) of
        undefined -> {error, {invalid_parameter_set, ParamSet}};
        Params -> {ok, Params}
    end.

expand_seed(Seed) ->
    Extended = crypto:hash(sha512, Seed),
    {binary:part(Extended, 0, 32), binary:part(Extended, 32, 32)}.

dilithium_keygen(Rho, K, #{k := KParam, l := L, eta := Eta} = Params) ->
    A = gen_matrix(Rho, KParam),
    {S1, S2} = gen_secret_polys(K, L, Eta, KParam),
    T0 = matrix_vector_mult(A, S1, S2),
    T1 = matrix_vector_mult(A, T0, lists:duplicate(L, zero_poly())),
    PublicKey = encode_public_key(Rho, T1, Params),
    PrivateKey = encode_private_key(K, S1, S2, T0, PublicKey, Params),
    {PublicKey, PrivateKey}.

gen_matrix(Rho, K) ->
    [gen_uniform_poly(<<Rho/binary, I:8, J:8>>) || I <- lists:seq(0, K-1), J <- lists:seq(0, K-1)].

gen_secret_polys(K, L, Eta, SeedSize) ->
    Seed = crypto:strong_rand_bytes(SeedSize),
    S1 = [gen_cbd_poly(<<Seed/binary, I:8>>, Eta) || I <- lists:seq(0, K-1)],
    S2 = [gen_cbd_poly(<<Seed/binary, (K+I):8>>, Eta) || I <- lists:seq(0, L-1)],
    {S1, S2}.

gen_uniform_poly(Seed) ->
    Coeffs = [crypto:bytes_to_integer(crypto:hash(sha256, <<Seed, I:32>>)) rem ?DILITHIUM_Q
              || I <- lists:seq(0, ?DILITHIUM_N-1)],
    << <<C:32/little>> || C <- Coeffs >>.

gen_cbd_poly(Seed, Eta) ->
    ExtendedSeed = crypto:hash(sha512, Seed),
    Coeffs = [cbd_sample(ExtendedSeed, I, Eta) || I <- lists:seq(0, ?DILITHIUM_N-1)],
    << <<C:32/little-signed>> || C <- Coeffs >>.

cbd_sample(Seed, Index, Eta) when Eta =< 32 ->
    Hash = crypto:hash(sha512, <<Seed/binary, Index:32>>),
    <<A:32/little, B:32/little, _/binary>> = Hash,
    Mask = (1 bsl Eta) - 1,
    (count_bits(A band Mask) - count_bits(B band Mask)).

count_bits(0) -> 0;
count_bits(N) -> (N band 1) + count_bits(N bsr 1).

matrix_vector_mult(Matrix, Vector, Error) ->
    lists:zipwith(fun(Row, E) ->
        Sum = lists:foldl(fun(Poly, Acc) -> poly_add(Acc, Poly) end, zero_poly(), Row),
        poly_add(Sum, E)
    end, chunk_matrix(Matrix, length(Vector)), Error).

poly_add(<<>>, <<>>) -> <<>>;
poly_add(<<A:32/little, RestA/binary>>, <<B:32/little, RestB/binary>>) ->
    Sum = (A + B) rem ?DILITHIUM_Q,
    <<Sum:32/little, (poly_add(RestA, RestB))/binary>>;
poly_add(A, <<>>) -> A;
poly_add(<<>>, B) -> B.

zero_poly() -> <<0:(?DILITHIUM_N*32)>>.

poly_sub(A, B) ->
    poly_add(A, poly_neg(B)).

poly_neg(Poly) ->
    << <<(?DILITHIUM_Q - C):32/little>> || <<C:32/little>> <= Poly >>.

poly_mult(A, B) ->
    poly_add(A, B).

generate_commitment(_S1, _T0, Mu, Randomness, #{k := K, l := L, gamma_1 := Gamma1}) ->
    A = gen_matrix(Mu, K),
    Y = matrix_vector_mult(A, lists:duplicate(K, Randomness), lists:duplicate(L, zero_poly())),
    Z = [gen_cbd_poly(<<Randomness/binary, I:8>>, Gamma1) || I <- lists:seq(0, L-1)],
    {Y, Z}.

compute_challenge(Message, Y, Mu, _) ->
    YBin = lists:flatten([Poly || Poly <- Y]),
    crypto:hash(sha256, <<Mu/binary, YBin/binary, Message/binary>>).

compute_response(C, Z, S1, #{l := L}) ->
    ZPrime = lists:zipwith(fun(Zi, Si) -> poly_add(Zi, poly_mult(C, Si)) end, Z, S1),
    H = lists:duplicate(L, zero_poly()),
    {ZPrime, H}.

recompute_Y(C, _ZPrime, H, T1, #{k := _K}) ->
    T1C = [poly_mult(T1i, C) || T1i <- T1],
    lists:zipwith(fun(T1Ci, Hi) -> poly_sub(T1Ci, Hi) end, T1C, H).

constant_time_compare(A, B) when byte_size(A) =/= byte_size(B) -> false;
constant_time_compare(A, B) -> crypto:exor(A, B) =:= <<0:(byte_size(A)*8)>>.

chunk_matrix(Matrix, K) -> chunk_list(Matrix, K).
chunk_list([], _) -> [];
chunk_list(List, N) ->
    {Chunk, Rest} = lists:split(erlang:min(N, length(List)), List),
    [Chunk | chunk_list(Rest, N)].

encode_public_key(Rho, T1, _) ->
    T1Bytes = lists:flatten([Poly || Poly <- T1]),
    <<Rho/binary, T1Bytes/binary>>.

encode_private_key(K, S1, S2, T0, PublicKey, _) ->
    S1Bytes = lists:flatten([Poly || Poly <- S1]),
    S2Bytes = lists:flatten([Poly || Poly <- S2]),
    T0Bytes = lists:flatten([Poly || Poly <- T0]),
    <<K/binary, S1Bytes/binary, S2Bytes/binary, T0Bytes/binary, PublicKey/binary>>.

encode_signature(C, ZPrime, H, _) ->
    ZPrimeBytes = lists:flatten([Poly || Poly <- ZPrime]),
    HBytes = lists:flatten([Poly || Poly <- H]),
    <<C/binary, ZPrimeBytes/binary, HBytes/binary>>.

decode_public_key(PublicKey, #{k := K, public_key_size := PubSize, seed_size := SeedSize}) ->
    T1Size = PubSize - SeedSize,
    PolySize = T1Size div K,
    <<Rho:SeedSize/binary, T1Bytes:T1Size/binary>> = PublicKey,
    T1 = [binary:part(T1Bytes, I * PolySize, PolySize) || I <- lists:seq(0, K-1)],
    {Rho, T1}.

decode_private_key(PrivateKey, #{k := K, l := L, private_key_size := PrivSize, seed_size := SeedSize}) ->
    S1Size = K * ?DILITHIUM_N * 4,
    S2Size = L * ?DILITHIUM_N * 4,
    T0Size = K * ?DILITHIUM_N * 4,
    PubSize = PrivSize - SeedSize - S1Size - S2Size - T0Size,
    <<Kval:SeedSize/binary,
      S1Bytes:S1Size/binary,
      S2Bytes:S2Size/binary,
      T0Bytes:T0Size/binary,
      PublicKey:PubSize/binary>> = PrivateKey,
    S1 = [binary:part(S1Bytes, I * ?DILITHIUM_N * 4, ?DILITHIUM_N * 4) || I <- lists:seq(0, K-1)],
    S2 = [binary:part(S2Bytes, I * ?DILITHIUM_N * 4, ?DILITHIUM_N * 4) || I <- lists:seq(0, L-1)],
    T0 = [binary:part(T0Bytes, I * ?DILITHIUM_N * 4, ?DILITHIUM_N * 4) || I <- lists:seq(0, K-1)],
    {Kval, S1, S2, T0, PublicKey}.

decode_signature(Signature, #{l := L, signature_size := SigSize, kappa := Kappa}) ->
    CSize = Kappa,
    ZPrimeSize = L * ?DILITHIUM_N * 4,
    HSize = SigSize - CSize - ZPrimeSize,
    <<C:CSize/binary, ZPrimeBytes:ZPrimeSize/binary, HBytes:HSize/binary>> = Signature,
    ZPrime = [binary:part(ZPrimeBytes, I * ?DILITHIUM_N * 4, ?DILITHIUM_N * 4) || I <- lists:seq(0, L-1)],
    H = [binary:part(HBytes, I * ?DILITHIUM_N * 4, ?DILITHIUM_N * 4) || I <- lists:seq(0, L-1)],
    {C, ZPrime, H}.

