%%%===================================================================
%%% Description: ML-KEM (CRYSTALS-Kyber) post-quantum key encapsulation
%%% Based on FIPS 203 standard with Alara entropy integration
%%%===================================================================
-module(keylara_mlkem).
-export([
    generate_keypair/2,
    encapsulate/2,
    decapsulate/3,
    validate_public_key/2,
    validate_private_key/2,
    validate_ciphertext/2,
    get_parameter_sizes/1
]).
-include("keylara.hrl").

%% ML-KEM parameter sets
-define(MLKEM_512, mlkem_512).
-define(MLKEM_768, mlkem_768).
-define(MLKEM_1024, mlkem_1024).

%% Parameter definitions
-define(MLKEM_PARAMS, #{
    mlkem_512 => #{
        k => 2,
        eta_1 => 3,
        eta_2 => 2,
        du => 10,
        dv => 4,
        public_key_size => 800,
        private_key_size => 1632,
        ciphertext_size => 768,
        shared_secret_size => 32
    },
    mlkem_768 => #{
        k => 3,
        eta_1 => 2,
        eta_2 => 2,
        du => 10,
        dv => 4,
        public_key_size => 1184,
        private_key_size => 2400,
        ciphertext_size => 1088,
        shared_secret_size => 32
    },
    mlkem_1024 => #{
        k => 4,
        eta_1 => 2,
        eta_2 => 2,
        du => 11,
        dv => 5,
        public_key_size => 1568,
        private_key_size => 3168,
        ciphertext_size => 1568,
        shared_secret_size => 32
    }
}).

%% Kyber constants
-define(KYBER_Q, 3329).
-define(KYBER_N, 256).
-define(KYBER_SYMBYTES, 32).

%%%===================================================================
%%% Types
%%%===================================================================
-type mlkem_param_set() :: mlkem_512 | mlkem_768 | mlkem_1024.
-type mlkem_public_key() :: binary().
-type mlkem_private_key() :: binary().
-type mlkem_ciphertext() :: binary().
-type mlkem_shared_secret() :: binary().

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Generate ML-KEM keypair using Alara distributed entropy
%% @param NetPid - Process ID of the Alara network
%% @param ParamSet - ML-KEM parameter set (mlkem_512, mlkem_768, or mlkem_1024)
%% @return {ok, {PublicKey, PrivateKey}} | {error, Reason}
-spec generate_keypair(pid(), mlkem_param_set()) -> 
    {ok, {mlkem_public_key(), mlkem_private_key()}} | keylara_error().
generate_keypair(NetPid, ParamSet) when is_pid(NetPid) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            try
                % Generate seed using Alara entropy
                case keylara:get_entropy_bytes(NetPid, ?KYBER_SYMBYTES) of
                    {ok, Seed} ->
                        % Key generation algorithm
                        {PublicKey, PrivateKey} = mlkem_keygen(Seed, Params),
                        {ok, {PublicKey, PrivateKey}};
                    {error, Reason} ->
                        {error, {entropy_generation_failed, Reason}}
                end
            catch
                Error:CatchReason:Stacktrace ->
                    {error, {keygen_failed, Error, CatchReason, Stacktrace}}
            end
    end;
generate_keypair(_NetPid, _ParamSet) ->
    {error, invalid_network_pid}.

%% @doc Encapsulate shared secret using ML-KEM
%% @param PublicKey - ML-KEM public key
%% @param ParamSet - ML-KEM parameter set
%% @return {ok, {Ciphertext, SharedSecret}} | {error, Reason}
-spec encapsulate(mlkem_public_key(), mlkem_param_set()) -> 
    {ok, {mlkem_ciphertext(), mlkem_shared_secret()}} | keylara_error().
encapsulate(PublicKey, ParamSet) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            case validate_public_key(PublicKey, ParamSet) of
                ok ->
                    try
                        % Generate random message
                        Message = crypto:strong_rand_bytes(?KYBER_SYMBYTES),
                        
                        % Encapsulation algorithm
                        {Ciphertext, SharedSecret} = mlkem_encaps(PublicKey, Message, Params),
                        {ok, {Ciphertext, SharedSecret}}
                    catch
                        Error:CatchReason:Stacktrace ->
                            {error, {encapsulation_failed, Error, CatchReason, Stacktrace}}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% @doc Decapsulate shared secret using ML-KEM
%% @param Ciphertext - ML-KEM ciphertext
%% @param PrivateKey - ML-KEM private key
%% @param ParamSet - ML-KEM parameter set
%% @return {ok, SharedSecret} | {error, Reason}
-spec decapsulate(mlkem_ciphertext(), mlkem_private_key(), mlkem_param_set()) -> 
    {ok, mlkem_shared_secret()} | keylara_error().
decapsulate(Ciphertext, PrivateKey, ParamSet) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            case validate_private_key(PrivateKey, ParamSet) of
                ok ->
                    case validate_ciphertext(Ciphertext, ParamSet) of
                        ok ->
                            try
                                % Decapsulation algorithm
                                SharedSecret = mlkem_decaps(Ciphertext, PrivateKey, Params),
                                {ok, SharedSecret}
                            catch
                                Error:CatchReason:Stacktrace ->
                                    {error, {decapsulation_failed, Error, CatchReason, Stacktrace}}
                            end;
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% @doc Validate ML-KEM public key format and size
%% @param PublicKey - Public key to validate
%% @param ParamSet - ML-KEM parameter set
%% @return ok | {error, Reason}
-spec validate_public_key(term(), mlkem_param_set()) -> ok | keylara_error().
validate_public_key(PublicKey, ParamSet) when is_binary(PublicKey) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        #{public_key_size := ExpectedSize} ->
            case byte_size(PublicKey) of
                ExpectedSize ->
                    ok;
                ActualSize ->
                    {error, {invalid_public_key_size, ActualSize, ExpectedSize}}
            end
    end;
validate_public_key(_PublicKey, _ParamSet) ->
    {error, invalid_public_key_format}.

%% @doc Validate ML-KEM private key format and size
%% @param PrivateKey - Private key to validate
%% @param ParamSet - ML-KEM parameter set
%% @return ok | {error, Reason}
-spec validate_private_key(term(), mlkem_param_set()) -> ok | keylara_error().
validate_private_key(PrivateKey, ParamSet) when is_binary(PrivateKey) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        #{private_key_size := ExpectedSize} ->
            case byte_size(PrivateKey) of
                ExpectedSize ->
                    ok;
                ActualSize ->
                    {error, {invalid_private_key_size, ActualSize, ExpectedSize}}
            end
    end;
validate_private_key(_PrivateKey, _ParamSet) ->
    {error, invalid_private_key_format}.

%% @doc Validate ML-KEM ciphertext format and size
%% @param Ciphertext - Ciphertext to validate
%% @param ParamSet - ML-KEM parameter set
%% @return ok | {error, Reason}
-spec validate_ciphertext(term(), mlkem_param_set()) -> ok | keylara_error().
validate_ciphertext(Ciphertext, ParamSet) when is_binary(Ciphertext) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        #{ciphertext_size := ExpectedSize} ->
            case byte_size(Ciphertext) of
                ExpectedSize ->
                    ok;
                ActualSize ->
                    {error, {invalid_ciphertext_size, ActualSize, ExpectedSize}}
            end
    end;
validate_ciphertext(_Ciphertext, _ParamSet) ->
    {error, invalid_ciphertext_format}.

%% @doc Get parameter sizes for given ML-KEM parameter set
%% @param ParamSet - ML-KEM parameter set
%% @return {ok, Sizes} | {error, Reason}
-spec get_parameter_sizes(mlkem_param_set()) -> 
    {ok, #{atom() => non_neg_integer()}} | keylara_error().
get_parameter_sizes(ParamSet) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            {ok, Params}
    end.

%%%===================================================================
%%% Internal ML-KEM Implementation
%%%===================================================================

%% @doc ML-KEM key generation algorithm
%% @param Seed - Random seed
%% @param Params - Parameter set
%% @return {PublicKey, PrivateKey}
-spec mlkem_keygen(binary(), map()) -> {binary(), binary()}.
mlkem_keygen(Seed, #{k := K} = Params) ->
    % Expand seed for polynomial generation
    {Rho, Sigma} = expand_seed(Seed),
    
    % Generate matrix A from rho
    A = gen_matrix(Rho, K),
    
    % Generate secret polynomial vector s
    S = gen_secret_vector(Sigma, K, maps:get(eta_1, Params)),
    
    % Generate error polynomial vector e
    E = gen_error_vector(Sigma, K, maps:get(eta_1, Params)),
    
    % Compute t = As + e
    T = matrix_vector_mult(A, S, E),
    
    % Encode public key
    PublicKey = encode_public_key(T, Rho, Params),
    
    % Encode private key
    PrivateKey = encode_private_key(S, PublicKey, Params),
    
    {PublicKey, PrivateKey}.

%% @doc ML-KEM encapsulation algorithm
%% @param PublicKey - Public key
%% @param Message - Random message
%% @param Params - Parameter set
%% @return {Ciphertext, SharedSecret}
-spec mlkem_encaps(binary(), binary(), map()) -> {binary(), binary()}.
mlkem_encaps(PublicKey, Message, Params) ->
    % Decode public key
    {T, Rho} = decode_public_key(PublicKey, Params),
    
    % Hash message and public key
    MessageHash = hash_message(Message, PublicKey),
    
    % Generate matrix A
    A = gen_matrix(Rho, maps:get(k, Params)),
    
    % Generate encryption randomness
    {R, E1, E2} = gen_encryption_randomness(MessageHash, Params),
    
    % Compute ciphertext components
    U = matrix_vector_mult_transpose(A, R, E1),
    V = vector_dot_product(T, R) + E2 + encode_message(Message, Params),
    
    % Encode ciphertext
    Ciphertext = encode_ciphertext(U, V, Params),
    
    % Derive shared secret
    SharedSecret = derive_shared_secret(Message, Ciphertext),
    
    {Ciphertext, SharedSecret}.

%% @doc ML-KEM decapsulation algorithm
%% @param Ciphertext - Ciphertext
%% @param PrivateKey - Private key
%% @param Params - Parameter set
%% @return SharedSecret
-spec mlkem_decaps(binary(), binary(), map()) -> binary().
mlkem_decaps(Ciphertext, PrivateKey, Params) ->
    % Decode private key
    {S, PublicKey} = decode_private_key(PrivateKey, Params),
    
    % Decode ciphertext
    {U, V} = decode_ciphertext(Ciphertext, Params),
    
    % Compute message
    MessageVector = V - vector_dot_product(S, U),
    Message = decode_message(MessageVector, Params),
    
    % Re-encrypt to verify
    {TestCiphertext, SharedSecret} = mlkem_encaps(PublicKey, Message, Params),
    
    % Constant-time comparison
    case constant_time_compare(Ciphertext, TestCiphertext) of
        true ->
            SharedSecret;
        false ->
            % Generate pseudo-random shared secret for failed decryption
            pseudo_random_secret(PrivateKey, Ciphertext)
    end.

%%%===================================================================
%%% Polynomial and Vector Operations
%%%===================================================================

%% @doc Generate matrix A from seed rho
-spec gen_matrix(binary(), pos_integer()) -> [binary()].
gen_matrix(Rho, K) ->
    [gen_uniform_poly(<<Rho/binary, I:8, J:8>>) || I <- lists:seq(0, K-1), J <- lists:seq(0, K-1)].

%% @doc Generate secret vector from sigma
-spec gen_secret_vector(binary(), pos_integer(), pos_integer()) -> [binary()].
gen_secret_vector(Sigma, K, Eta) ->
    [gen_cbd_poly(<<Sigma/binary, I:8>>, Eta) || I <- lists:seq(0, K-1)].

%% @doc Generate error vector
-spec gen_error_vector(binary(), pos_integer(), pos_integer()) -> [binary()].
gen_error_vector(Sigma, K, Eta) ->
    [gen_cbd_poly(<<Sigma/binary, (K+I):8>>, Eta) || I <- lists:seq(0, K-1)].

%% @doc Matrix-vector multiplication with error
-spec matrix_vector_mult([binary()], [binary()], [binary()]) -> [binary()].
matrix_vector_mult(Matrix, Vector, Error) ->
    % Simplified implementation - real implementation would use NTT
    lists:zipwith(fun(Row, E) ->
        Sum = lists:foldl(fun(Poly, Acc) ->
            poly_add(Acc, Poly)
        end, <<0:(?KYBER_N*16)>>, Row),
        poly_add(Sum, E)
    end, chunk_matrix(Matrix, length(Vector)), Error).

%% @doc Generate uniform polynomial from seed
-spec gen_uniform_poly(binary()) -> binary().
gen_uniform_poly(Seed) ->
    % Use SHAKE-128 to generate uniform coefficients
    _ExtendedSeed = crypto:hash(sha3_256, Seed),
    % Simplified: generate random coefficients mod q
    Coeffs = [crypto:bytes_to_integer(crypto:strong_rand_bytes(2)) rem ?KYBER_Q 
              || _ <- lists:seq(1, ?KYBER_N)],
    << <<C:16/little>> || C <- Coeffs >>.

%% @doc Generate CBD (Centered Binomial Distribution) polynomial
-spec gen_cbd_poly(binary(), pos_integer()) -> binary().
gen_cbd_poly(Seed, Eta) ->
    ExtendedSeed = crypto:hash(sha3_256, Seed),
    % Simplified CBD sampling
    Coeffs = [cbd_sample(ExtendedSeed, I, Eta) || I <- lists:seq(0, ?KYBER_N-1)],
    << <<C:16/little-signed>> || C <- Coeffs >>.

%% @doc Sample from centered binomial distribution
cbd_sample(Seed, Index, Eta) when
  is_binary(Seed),
  is_integer(Index), Index >= 0,
  is_integer(Eta), Eta > 0, Eta =< 32 ->

  SeedSize = byte_size(Seed),
  Offset = Index rem SeedSize,
  RemainingRaw = SeedSize - Offset,
  Remaining = if RemainingRaw < 0 -> 0; true -> RemainingRaw end,
  N = min(4, Remaining),

  PadSizeBits = (4 - N) * 8,
  PadSizeBitsSafe = if PadSizeBits < 0 -> 0; true -> PadSizeBits end,

  Buf = case N of
    4 -> binary:part(Seed, Offset, 4);
    N1 when N1 > 0 ->
      Part = binary:part(Seed, Offset, N1),
      <<Part/binary, 0:PadSizeBitsSafe>>;
    _ -> <<0,0,0,0>>
  end,

  <<Bits:32/little>> = Buf,

  Mask = (1 bsl Eta) - 1,
  A = count_bits(Bits band Mask),
  B = count_bits((Bits bsr Eta) band Mask),
  A - B;

cbd_sample(_, _, _) -> 0.

%% @doc Count number of set bits
-spec count_bits(non_neg_integer()) -> non_neg_integer().
count_bits(0) -> 0;
count_bits(N) -> (N band 1) + count_bits(N bsr 1).

%% @doc Polynomial addition
-spec poly_add(binary(), binary()) -> binary().
poly_add(<<>>, <<>>) -> <<>>;
poly_add(<<A:16/little, RestA/binary>>, <<B:16/little, RestB/binary>>) ->
    Sum = (A + B) rem ?KYBER_Q,
    <<Sum:16/little, (poly_add(RestA, RestB))/binary>>;
poly_add(A, <<>>) -> A;
poly_add(<<>>, B) -> B.

%% @doc Vector dot product
-spec vector_dot_product([binary()], [binary()]) -> binary().
vector_dot_product(V1, V2) ->
    Products = lists:zipwith(fun poly_multiply/2, V1, V2),
    lists:foldl(fun poly_add/2, <<0:(?KYBER_N*16)>>, Products).

%% @doc Simplified polynomial multiplication (should use NTT in real implementation)
-spec poly_multiply(binary(), binary()) -> binary().
poly_multiply(A, B) ->
    % Simplified - real implementation would use Number Theoretic Transform
    poly_add(A, B). % Placeholder

%%%===================================================================
%%% Encoding/Decoding Functions
%%%===================================================================

%% @doc Encode public key
-spec encode_public_key([binary()], binary(), map()) -> binary().
encode_public_key(T, Rho, _Params) ->
    TBytes = << <<Poly/binary>> || Poly <- T >>,
    <<TBytes/binary, Rho/binary>>.

%% @doc Encode private key
-spec encode_private_key([binary()], binary(), map()) -> binary().
encode_private_key(S, PublicKey, _Params) ->
    SBytes = << <<Poly/binary>> || Poly <- S >>,
    Hash = crypto:hash(sha3_256, PublicKey),
    <<SBytes/binary, PublicKey/binary, Hash/binary>>.

%% @doc Encode ciphertext
-spec encode_ciphertext([binary()], binary(), map()) -> binary().
encode_ciphertext(U, V, _Params) ->
    UBytes = << <<Poly/binary>> || Poly <- U >>,
    <<UBytes/binary, V/binary>>.

%% @doc Decode public key
-spec decode_public_key(binary(), map()) -> {[binary()], binary()}.
decode_public_key(PublicKey, #{k := K}) ->
    PolySize = ?KYBER_N * 2, % 16 bits per coefficient
    TSize = K * PolySize,
    <<TBytes:TSize/binary, Rho/binary>> = PublicKey,
    T = [binary:part(TBytes, I * PolySize, PolySize) || I <- lists:seq(0, K-1)],
    {T, Rho}.

%% @doc Decode private key
-spec decode_private_key(binary(), map()) -> {[binary()], binary()}.
decode_private_key(PrivateKey, #{k := K, public_key_size := PubSize}) ->
    PolySize = ?KYBER_N * 2,
    SSize = K * PolySize,
    <<SBytes:SSize/binary, PublicKey:PubSize/binary, _Hash/binary>> = PrivateKey,
    S = [binary:part(SBytes, I * PolySize, PolySize) || I <- lists:seq(0, K-1)],
    {S, PublicKey}.

%% @doc Decode ciphertext
-spec decode_ciphertext(binary(), map()) -> {[binary()], binary()}.
decode_ciphertext(Ciphertext, #{k := K}) ->
    PolySize = ?KYBER_N * 2,
    USize = K * PolySize,
    <<UBytes:USize/binary, V/binary>> = Ciphertext,
    U = [binary:part(UBytes, I * PolySize, PolySize) || I <- lists:seq(0, K-1)],
    {U, V}.

%%%===================================================================
%%% Utility Functions
%%%===================================================================

%% @doc Expand seed into rho and sigma
-spec expand_seed(binary()) -> {binary(), binary()}.
expand_seed(Seed) ->
    Extended = crypto:hash(sha3_512, Seed),
    {binary:part(Extended, 0, 32), binary:part(Extended, 32, 32)}.

%% @doc Hash message with public key
-spec hash_message(binary(), binary()) -> binary().
hash_message(Message, PublicKey) ->
    crypto:hash(sha3_256, <<Message/binary, PublicKey/binary>>).

%% @doc Generate encryption randomness
-spec gen_encryption_randomness(binary(), map()) -> {[binary()], [binary()], binary()}.
gen_encryption_randomness(Hash, #{k := K, eta_2 := Eta2}) ->
    R = [gen_cbd_poly(<<Hash/binary, I:8>>, Eta2) || I <- lists:seq(0, K-1)],
    E1 = [gen_cbd_poly(<<Hash/binary, (K+I):8>>, Eta2) || I <- lists:seq(0, K-1)],
    E2 = gen_cbd_poly(<<Hash/binary, (2*K):8>>, Eta2),
    {R, E1, E2}.

%% @doc Matrix-vector multiplication (transpose)
-spec matrix_vector_mult_transpose([binary()], [binary()], [binary()]) -> [binary()].
matrix_vector_mult_transpose(Matrix, Vector, Error) ->
    % Simplified implementation
    lists:zipwith(fun poly_add/2, 
                 matrix_vector_mult(Matrix, Vector, lists:duplicate(length(Vector), <<0:(?KYBER_N*16)>>)), 
                 Error).

%% @doc Encode message into polynomial
-spec encode_message(binary(), map()) -> binary().
encode_message(Message, _Params) ->
    % Simplified message encoding
    <<Message/binary, 0:((?KYBER_N * 2 - byte_size(Message)) * 8)>>.

%% @doc Decode message from polynomial
-spec decode_message(binary(), map()) -> binary().
decode_message(MessagePoly, _Params) ->
    % Simplified message decoding
    binary:part(MessagePoly, 0, ?KYBER_SYMBYTES).

%% @doc Derive shared secret
-spec derive_shared_secret(binary(), binary()) -> binary().
derive_shared_secret(Message, Ciphertext) ->
    crypto:hash(sha3_256, <<Message/binary, Ciphertext/binary>>).

%% @doc Constant-time binary comparison
-spec constant_time_compare(binary(), binary()) -> boolean().
constant_time_compare(A, B) when byte_size(A) =/= byte_size(B) ->
    false;
constant_time_compare(A, B) ->
    crypto:exor(A, B) =:= <<0:(byte_size(A)*8)>>.

%% @doc Generate pseudo-random secret for failed decryption
-spec pseudo_random_secret(binary(), binary()) -> binary().
pseudo_random_secret(PrivateKey, Ciphertext) ->
    crypto:hash(sha3_256, <<PrivateKey/binary, Ciphertext/binary>>).

%% @doc Chunk matrix into rows
-spec chunk_matrix([binary()], pos_integer()) -> [[binary()]].
chunk_matrix(Matrix, K) ->
    chunk_list(Matrix, K).

%% @doc Chunk list into sublists of specified size
-spec chunk_list([T], pos_integer()) -> [[T]].
chunk_list([], _) -> [];
chunk_list(List, N) ->
    {Chunk, Rest} = lists:split(min(N, length(List)), List),
    [Chunk | chunk_list(Rest, N)].

%%%===================================================================
%%% Unit Tests
%%%===================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

parameter_sizes_test() ->
    {ok, Sizes512} = get_parameter_sizes(mlkem_512),
    ?assertEqual(800, maps:get(public_key_size, Sizes512)),
    ?assertEqual(1632, maps:get(private_key_size, Sizes512)),
    
    {ok, Sizes768} = get_parameter_sizes(mlkem_768),
    ?assertEqual(1184, maps:get(public_key_size, Sizes768)),
    
    {ok, Sizes1024} = get_parameter_sizes(mlkem_1024),
    ?assertEqual(1568, maps:get(public_key_size, Sizes1024)).

validation_test() ->
    ValidPubKey512 = crypto:strong_rand_bytes(800),
    ValidPrivKey512 = crypto:strong_rand_bytes(1632),
    ValidCiphertext512 = crypto:strong_rand_bytes(768),
    
    ?assertEqual(ok, validate_public_key(ValidPubKey512, mlkem_512)),
    ?assertEqual(ok, validate_private_key(ValidPrivKey512, mlkem_512)),
    ?assertEqual(ok, validate_ciphertext(ValidCiphertext512, mlkem_512)),
    
    InvalidPubKey = crypto:strong_rand_bytes(100),
    ?assertMatch({error, _}, validate_public_key(InvalidPubKey, mlkem_512)).

cbd_sample_test() ->
    Seed = crypto:strong_rand_bytes(32),
    Sample1 = cbd_sample(Seed, 0, 2),
    Sample2 = cbd_sample(Seed, 1, 2),
    
    ?assert(Sample1 >= -2 andalso Sample1 =< 2),
    ?assert(Sample2 >= -2 andalso Sample2 =< 2).

count_bits_test() ->
    ?assertEqual(0, count_bits(0)),
    ?assertEqual(1, count_bits(1)),
    ?assertEqual(2, count_bits(3)),
    ?assertEqual(4, count_bits(15)),
    ?assertEqual(8, count_bits(255)).

constant_time_compare_test() ->
    A = <<1, 2, 3, 4>>,
    B = <<1, 2, 3, 4>>,
    C = <<1, 2, 3, 5>>,
    D = <<1, 2, 3>>,
    
    ?assert(constant_time_compare(A, B)),
    ?assertNot(constant_time_compare(A, C)),
    ?assertNot(constant_time_compare(A, D)).

-endif.
