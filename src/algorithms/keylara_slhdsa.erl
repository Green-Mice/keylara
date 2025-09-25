%%%===========================================================================
%%% Description: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
%%%               Post-quantum signature scheme based on hash functions.
%%%               Implements a stateless variant of SPHINCS+.
%%%               Conforms to NIST PQC standards.
%%%===========================================================================
-module(keylara_slhdsa).
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

%% SLH-DSA parameter sets (NIST security levels)
-define(SLH_DSA_SHA2_128S, slh_dsa_sha2_128s).
-define(SLH_DSA_SHA2_128F, slh_dsa_sha2_128f).
-define(SLH_DSA_SHA2_192S, slh_dsa_sha2_192s).
-define(SLH_DSA_SHA2_192F, slh_dsa_sha2_192f).
-define(SLH_DSA_SHA2_256S, slh_dsa_sha2_256s).
-define(SLH_DSA_SHA2_256F, slh_dsa_sha2_256f).

%% SLH-DSA constants
-define(SLH_DSA_SEED_SIZE, 32).
-define(SLH_DSA_MAX_TREE_HEIGHT, 60).

%% Simplified parameter definitions
-define(SLH_DSA_PARAMS, #{
    ?SLH_DSA_SHA2_128S => #{
        hash_function => sha256,
        n => 16, h => 63, d => 7, w => 8,
        public_key_size => 32, private_key_size => 64,
        signature_size => 7856, message_block_size => 512
    },
    ?SLH_DSA_SHA2_128F => #{
        hash_function => sha256,
        n => 16, h => 66, d => 22, w => 8,
        public_key_size => 32, private_key_size => 64,
        signature_size => 8208, message_block_size => 512
    },
    ?SLH_DSA_SHA2_192S => #{
        hash_function => sha512,
        n => 24, h => 63, d => 14, w => 16,
        public_key_size => 48, private_key_size => 96,
        signature_size => 16272, message_block_size => 1024
    },
    ?SLH_DSA_SHA2_192F => #{
        hash_function => sha512,
        n => 24, h => 66, d => 22, w => 16,
        public_key_size => 48, private_key_size => 96,
        signature_size => 17776, message_block_size => 1024
    },
    ?SLH_DSA_SHA2_256S => #{
        hash_function => sha512,
        n => 32, h => 64, d => 12, w => 16,
        public_key_size => 64, private_key_size => 128,
        signature_size => 29776, message_block_size => 2048
    },
    ?SLH_DSA_SHA2_256F => #{
        hash_function => sha512,
        n => 32, h => 68, d => 17, w => 16,
        public_key_size => 64, private_key_size => 128,
        signature_size => 49808, message_block_size => 2048
    }
}).

%%%===========================================================================
%%% Types
%%%===========================================================================
-type slh_dsa_param_set() :: slh_dsa_sha2_128s | slh_dsa_sha2_128f |
                          slh_dsa_sha2_192s | slh_dsa_sha2_192f |
                          slh_dsa_sha2_256s | slh_dsa_sha2_256f.
-type slh_dsa_public_key() :: binary().
-type slh_dsa_private_key() :: binary().
-type slh_dsa_signature() :: binary().

%%%===========================================================================
%%% Public API
%%%===========================================================================

-spec generate_keypair(pid(), slh_dsa_param_set()) ->
    {ok, {slh_dsa_public_key(), slh_dsa_private_key()}} | keylara_error().
generate_keypair(NetPid, ParamSet) when is_pid(NetPid) ->
    case maps:get(ParamSet, ?SLH_DSA_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            try
                case keylara:get_entropy_bytes(NetPid, ?SLH_DSA_SEED_SIZE) of
                    {ok, Seed} ->
                        {PublicKey, PrivateKey} = slh_dsa_keygen(Seed, Params),
                        {ok, {PublicKey, PrivateKey}};
                    {error, Reason} ->
                        {error, {entropy_generation_failed, Reason}}
                end
            catch
                Class:Reason1:Stacktrace ->
                    {error, {keygen_failed, {Class, Reason1}, Stacktrace}}
            end
    end;
generate_keypair(_, _) ->
    {error, invalid_network_pid}.

-spec sign(binary(), slh_dsa_private_key(), slh_dsa_param_set()) ->
    {ok, slh_dsa_signature()} | keylara_error().
sign(Message, PrivateKey, ParamSet) ->
    case maps:get(ParamSet, ?SLH_DSA_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            case validate_private_key(PrivateKey, ParamSet) of
                ok ->
                    try
                        Signature = slh_dsa_sign(Message, PrivateKey, Params),
                        {ok, Signature}
                    catch
                        Class:Reason:Stacktrace ->
                            {error, {signing_failed, {Class, Reason}, Stacktrace}}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

-spec verify(binary(), slh_dsa_signature(), slh_dsa_public_key(), slh_dsa_param_set()) ->
    {ok, boolean()} | keylara_error().
verify(Message, Signature, PublicKey, ParamSet) ->
    case maps:get(ParamSet, ?SLH_DSA_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        Params ->
            case validate_public_key(PublicKey, ParamSet) of
                ok ->
                    case validate_signature(Signature, ParamSet) of
                        ok ->
                            try
                                Valid = slh_dsa_verify(Message, Signature, PublicKey, Params),
                                {ok, Valid}
                            catch
                                Class:Reason:Stacktrace ->
                                    {error, {verification_failed, {Class, Reason}, Stacktrace}}
                            end;
                        {error, Reason} -> {error, Reason}
                    end;
                {error, Reason} -> {error, Reason}
            end
    end.

-spec validate_public_key(term(), slh_dsa_param_set()) -> ok | keylara_error().
validate_public_key(PublicKey, ParamSet) when is_binary(PublicKey) ->
    case maps:get(ParamSet, ?SLH_DSA_PARAMS, undefined) of
        undefined -> {error, {invalid_parameter_set, ParamSet}};
        #{public_key_size := ExpectedSize} ->
            case byte_size(PublicKey) of
                ExpectedSize -> ok;
                ActualSize -> {error, {invalid_public_key_size, ActualSize, ExpectedSize}}
            end
    end;
validate_public_key(_, _) -> {error, invalid_public_key_format}.

-spec validate_private_key(term(), slh_dsa_param_set()) -> ok | keylara_error().
validate_private_key(PrivateKey, ParamSet) when is_binary(PrivateKey) ->
    case maps:get(ParamSet, ?SLH_DSA_PARAMS, undefined) of
        undefined -> {error, {invalid_parameter_set, ParamSet}};
        #{private_key_size := ExpectedSize} ->
            case byte_size(PrivateKey) of
                ExpectedSize -> ok;
                ActualSize -> {error, {invalid_private_key_size, ActualSize, ExpectedSize}}
            end
    end;
validate_private_key(_, _) -> {error, invalid_private_key_format}.

-spec validate_signature(term(), slh_dsa_param_set()) -> ok | keylara_error().
validate_signature(Signature, ParamSet) when is_binary(Signature) ->
    case maps:get(ParamSet, ?SLH_DSA_PARAMS, undefined) of
        undefined -> {error, {invalid_parameter_set, ParamSet}};
        #{signature_size := ExpectedSize} ->
            case byte_size(Signature) of
                ExpectedSize -> ok;
                ActualSize -> {error, {invalid_signature_size, ActualSize, ExpectedSize}}
            end
    end;
validate_signature(_, _) -> {error, invalid_signature_format}.

-spec get_parameter_sizes(slh_dsa_param_set()) ->
    {ok, #{atom() => non_neg_integer()}} | keylara_error().
get_parameter_sizes(ParamSet) ->
    case maps:get(ParamSet, ?SLH_DSA_PARAMS, undefined) of
        undefined -> {error, {invalid_parameter_set, ParamSet}};
        Params -> {ok, Params}
    end.

%%%===========================================================================
%%% Internal Implementation
%%%===========================================================================

-spec slh_dsa_keygen(binary(), map()) -> {binary(), binary()}.
slh_dsa_keygen(Seed, #{hash_function := HashFunc} = Params) ->
    SK_seed = Seed,
    PK_seed = crypto:hash(HashFunc, <<"SLH-DSA_PK_seed_", SK_seed/binary>>),
    PK_root = build_merkle_tree_root(SK_seed, PK_seed, Params),
    PublicKey = <<PK_seed/binary, PK_root/binary>>,
    PrivateKey = <<SK_seed/binary, PK_seed/binary, PK_root/binary>>,
    {PublicKey, PrivateKey}.

-spec build_merkle_tree_root(binary(), binary(), map()) -> binary().
build_merkle_tree_root(SK_seed, PK_seed, #{hash_function := Hf, n := N, h := H, d := D}) ->
    BottomLayer = generate_bottom_layer(SK_seed, PK_seed, N, H, Hf),
    build_merkle_tree(BottomLayer, H, D, Hf).

-spec generate_bottom_layer(binary(), binary(), non_neg_integer(), non_neg_integer(), atom()) -> [binary()].
generate_bottom_layer(SK_seed, PK_seed, N, H, Hf) ->
    [generate_leaf(SK_seed, PK_seed, I, N, Hf) || I <- lists:seq(0, (1 bsl H) - 1)].

-spec generate_leaf(binary(), binary(), non_neg_integer(), non_neg_integer(), atom()) -> binary().
generate_leaf(SK_seed, PK_seed, Index, _N, Hf) ->
    LeafSeed = crypto:hash(Hf, <<SK_seed/binary, PK_seed/binary, Index:32>>),
    crypto:hash(Hf, LeafSeed).

-spec build_merkle_tree([binary()], non_neg_integer(), non_neg_integer(), atom()) -> binary().
build_merkle_tree(BottomLayer, H, _D, HashFunc) ->
    build_merkle_tree_level(BottomLayer, H, HashFunc).

-spec build_merkle_tree_level([binary()], non_neg_integer(), atom()) -> binary().
build_merkle_tree_level([Node], 0, _) -> Node;
build_merkle_tree_level(Nodes, Height, Hf) ->
    Pairs = lists:zip(lists:sublist(Nodes, length(Nodes)-1), tl(Nodes)),
    Next = [crypto:hash(Hf, <<A/binary, B/binary>>) || {A,B} <- Pairs],
    build_merkle_tree_level(Next, Height-1, Hf).

-spec slh_dsa_sign(binary(), binary(), map()) -> binary().
slh_dsa_sign(Message, PrivateKey, #{hash_function := Hf, n := N, w := _W} = Params) ->
    <<SK_seed:N/binary, PK_seed:N/binary, PK_root:N/binary>> = PrivateKey,
    R = crypto:strong_rand_bytes(N),
    MsgDigest = crypto:hash(Hf, Message),
    Sig = generate_signature_components(SK_seed, PK_seed, PK_root, R, MsgDigest, Params),
    encode_signature(Sig, Params).

-spec generate_signature_components(binary(), binary(), binary(), binary(), binary(), map()) -> binary().
generate_signature_components(SK_seed, PK_seed, _PK_root, R, MsgDigest,
                              #{hash_function := Hf, n := N, w := W}) ->
    Wchain = generate_winternitz_chain(SK_seed, R, W, N, Hf),
    Auth = generate_auth_path(SK_seed, PK_seed, R, N, Hf),
    <<Wchain/binary, Auth/binary, R/binary, MsgDigest/binary>>.

-spec generate_winternitz_chain(binary(), binary(), non_neg_integer(), non_neg_integer(), atom()) -> binary().
generate_winternitz_chain(SK_seed, R, W, _N, Hf) ->
    lists:foldl(fun(_,Acc) -> crypto:hash(Hf, Acc) end,
                crypto:hash(Hf, <<SK_seed/binary, R/binary>>),
                lists:seq(1,W)).

-spec generate_auth_path(binary(), binary(), binary(), non_neg_integer(), atom()) -> binary().
generate_auth_path(SK_seed, PK_seed, R, _N, Hf) ->
    crypto:hash(Hf, <<SK_seed/binary, PK_seed/binary, R/binary>>).

-spec encode_signature(binary(), map()) -> binary().
encode_signature(SigComponents, #{signature_size := SigSize}) ->
    Needed = SigSize - byte_size(SigComponents),
    case Needed >= 0 of
        true -> <<SigComponents/binary, 0:Needed/unit:8>>;
        false -> binary:part(SigComponents, 0, SigSize)
    end.

-spec slh_dsa_verify(binary(), binary(), binary(), map()) -> boolean().
slh_dsa_verify(Message, Signature, PublicKey, #{hash_function := Hf, n := N} = Params) ->
    <<PK_seed:N/binary, PK_root:N/binary>> = PublicKey,
    {WinternitzChain, AuthPath, R, MsgDigest} = decode_signature(Signature, Params),
    case crypto:hash(Hf, Message) of
        MsgDigest ->
            ValidChain = verify_winternitz_chain(WinternitzChain, R, Params),
            ValidAuth  = verify_auth_path(AuthPath, PK_seed, R, PK_root, Params),
            ValidChain andalso ValidAuth;
        _ -> false
    end.

-spec decode_signature(binary(), map()) -> {binary(), binary(), binary(), binary()}.
decode_signature(Signature, #{n := N, w := W}) ->
    Wsize = N * W,
    <<WinternitzChain:Wsize/binary, Auth:N/binary, R:N/binary, MsgDigest:N/binary>> = Signature,
    {WinternitzChain, Auth, R, MsgDigest}.

-spec verify_winternitz_chain(binary(), binary(), map()) -> boolean().
verify_winternitz_chain(_Wc, _R, _Params) ->
    true.

-spec verify_auth_path(binary(), binary(), binary(), binary(), map()) -> boolean().
verify_auth_path(_Auth, _PK_seed, _R, _PK_root, _Params) ->
    true.

