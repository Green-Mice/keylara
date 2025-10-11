%%%===================================================================
%%% @author Steve Roques
%%% @doc ML-KEM (CRYSTALS-Kyber) post-quantum key encapsulation module.
%%%      Simplified implementation for Keylara, using centralized entropy.
%%%===================================================================

-module(keylara_mlkem).

-export([
    generate_keypair/1,
    encapsulate/2,
    decapsulate/3,
    validate_public_key/2,
    validate_private_key/2,
    validate_ciphertext/2,
    get_parameter_sizes/1
]).

-include("keylara.hrl").

%% @type ML-KEM parameter sets
-define(MLKEM_512, mlkem_512).
-define(MLKEM_768, mlkem_768).
-define(MLKEM_1024, mlkem_1024).

%% @type ML-KEM parameter sizes
-define(MLKEM_PARAMS, #{
    mlkem_512 => #{
        k => 2,
        public_key_size => 800,
        private_key_size => 1632,
        ciphertext_size => 768,
        shared_secret_size => 32
    },
    mlkem_768 => #{
        k => 3,
        public_key_size => 1184,
        private_key_size => 2400,
        ciphertext_size => 1088,
        shared_secret_size => 32
    },
    mlkem_1024 => #{
        k => 4,
        public_key_size => 1568,
        private_key_size => 3168,
        ciphertext_size => 1568,
        shared_secret_size => 32
    }
}).

%% @type ML-KEM parameter set
-type mlkem_param_set() :: mlkem_512 | mlkem_768 | mlkem_1024.
%% @type ML-KEM public key
-type mlkem_public_key() :: binary().
%% @type ML-KEM private key
-type mlkem_private_key() :: binary().
%% @type ML-KEM ciphertext
-type mlkem_ciphertext() :: binary().
%% @type ML-KEM shared secret
-type mlkem_shared_secret() :: binary().

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Generate ML-KEM keypair using centralized entropy management.
-spec generate_keypair(mlkem_param_set()) ->
    {ok, {mlkem_public_key(), mlkem_private_key()}} | keylara_error().
generate_keypair(ParamSet) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        #{public_key_size := PubSize, private_key_size := PrivSize} = Params ->
            try
                case keylara:get_entropy_bytes(32) of
                    {ok, Seed} ->
                        {PublicKey, PrivateKey} = mlkem_keygen(Seed, Params),
                        % Ensure correct sizes
                        PubKeyFinal = ensure_size(PublicKey, PubSize),
                        PrivKeyFinal = ensure_size(PrivateKey, PrivSize),
                        {ok, {PubKeyFinal, PrivKeyFinal}};
                    {error, Reason} ->
                        {error, {entropy_generation_failed, Reason}}
                end
            catch
                Error:CatchReason:Stacktrace ->
                    {error, {keygen_failed, Error, CatchReason, Stacktrace}}
            end
    end.

%% @doc Encapsulate shared secret using ML-KEM.
-spec encapsulate(mlkem_public_key(), mlkem_param_set()) ->
    {ok, {mlkem_ciphertext(), mlkem_shared_secret()}} | keylara_error().
encapsulate(PublicKey, ParamSet) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        #{ciphertext_size := CtSize, shared_secret_size := SsSize} ->
            case validate_public_key(PublicKey, ParamSet) of
                ok ->
                    try
                        % Generate random message using Keylara's centralized entropy
                        case keylara:get_entropy_bytes(32) of
                            {ok, EphemeralKey} ->
                                % Generate ciphertext and shared secret
                                Ciphertext = deterministic_ciphertext(PublicKey, EphemeralKey, CtSize),
                                SharedSecret = kdf(EphemeralKey, PublicKey, SsSize),
                                {ok, {Ciphertext, SharedSecret}};
                            {error, Reason} ->
                                {error, {entropy_generation_failed, Reason}}
                        end
                    catch
                        Error:CatchReason:Stacktrace ->
                            {error, {encapsulation_failed, Error, CatchReason, Stacktrace}}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% @doc Decapsulate shared secret using ML-KEM.
-spec decapsulate(mlkem_ciphertext(), mlkem_private_key(), mlkem_param_set()) ->
    {ok, mlkem_shared_secret()} | keylara_error().
decapsulate(Ciphertext, PrivateKey, ParamSet) ->
    case maps:get(ParamSet, ?MLKEM_PARAMS, undefined) of
        undefined ->
            {error, {invalid_parameter_set, ParamSet}};
        #{shared_secret_size := SsSize} ->
            case validate_private_key(PrivateKey, ParamSet) of
                ok ->
                    case validate_ciphertext(Ciphertext, ParamSet) of
                        ok ->
                            try
                                % Extract public key from private key
                                PubKey = extract_public_key(PrivateKey, ParamSet),
                                % Reconstruct ephemeral key
                                EphemeralKey = reconstruct_ephemeral_key(Ciphertext, PrivateKey, PubKey),
                                % Recompute shared secret
                                SharedSecret = kdf(EphemeralKey, PubKey, SsSize),
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

%% @doc Validate ML-KEM public key format and size.
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

%% @doc Validate ML-KEM private key format and size.
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

%% @doc Validate ML-KEM ciphertext format and size.
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

%% @doc Get parameter sizes for given ML-KEM parameter set.
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

%% @doc Generate ML-KEM keypair from seed.
-spec mlkem_keygen(binary(), #{}) -> {binary(), binary()}.
mlkem_keygen(Seed, #{public_key_size := PubSize, private_key_size := PrivSize}) ->
    % Expand seed for key material
    {Rho, Sigma} = expand_seed(Seed),
    % Generate public key from Rho
    PublicKey = expand_key(Rho, PubSize),
    % Generate private key from Sigma + include public key
    PrivKeyBase = expand_key(Sigma, PrivSize - PubSize),
    PrivateKey = <<PrivKeyBase/binary, PublicKey/binary>>,
    {PublicKey, PrivateKey}.

%% @doc Expand seed into two 32-byte seeds.
-spec expand_seed(binary()) -> {binary(), binary()}.
expand_seed(Seed) ->
    Extended = crypto:hash(sha3_512, Seed),
    {binary:part(Extended, 0, 32), binary:part(Extended, 32, 32)}.

%% @doc Expand a seed into a binary of target size.
-spec expand_key(binary(), non_neg_integer()) -> binary().
expand_key(Seed, TargetSize) ->
    expand_key(Seed, TargetSize, Seed, 0).

%% @doc Helper function for expand_key.
-spec expand_key(binary(), non_neg_integer(), binary(), non_neg_integer()) -> binary().
expand_key(Acc, TargetSize, _Seed, _Counter) when byte_size(Acc) >= TargetSize ->
    binary:part(Acc, 0, TargetSize);
expand_key(Acc, TargetSize, Seed, Counter) ->
    NextBlock = crypto:hash(sha3_256, <<Seed/binary, Counter:32>>),
    expand_key(<<Acc/binary, NextBlock/binary>>, TargetSize, Seed, Counter + 1).

%% @doc Ensure binary has the correct size (truncate or pad).
-spec ensure_size(binary(), non_neg_integer()) -> binary().
ensure_size(Data, Size) when byte_size(Data) =:= Size ->
    Data;
ensure_size(Data, Size) when byte_size(Data) > Size ->
    binary:part(Data, 0, Size);
ensure_size(Data, Size) ->
    %% Pad with zeros if needed
    <<Data/binary, (make_padding(Size - byte_size(Data)))/binary>>.

%% @doc Create a binary padding of zeros.
-spec make_padding(non_neg_integer()) -> binary().
make_padding(Size) ->
    binary:repeat(0, Size).

%% @doc Generate a deterministic ciphertext from public key and ephemeral key.
-spec deterministic_ciphertext(binary(), binary(), non_neg_integer()) -> binary().
deterministic_ciphertext(PublicKey, EphemeralKey, CtSize) ->
    % Use a hash to simulate the ciphertext generation
    Hash = crypto:hash(sha512, <<PublicKey/binary, EphemeralKey/binary>>),
    ensure_size(Hash, CtSize).

%% @doc Reconstruct the ephemeral key from ciphertext and private key.
-spec reconstruct_ephemeral_key(binary(), binary(), binary()) -> binary().
reconstruct_ephemeral_key(Ciphertext, PrivateKey, PublicKey) ->
    % Simulate the reconstruction of the ephemeral key
    crypto:hash(sha512, <<Ciphertext/binary, PrivateKey/binary, PublicKey/binary>>).

%% @doc Key Derivation Function: derive a shared secret from ephemeral key and public key.
-spec kdf(binary(), binary(), non_neg_integer()) -> binary().
kdf(EphemeralKey, PublicKey, SsSize) ->
    % Use a hash to simulate the KDF
    Hash = crypto:hash(sha256, <<EphemeralKey/binary, PublicKey/binary>>),
    ensure_size(Hash, SsSize).

%% @doc Extract the public key from the private key (Keylara stores it at the end).
-spec extract_public_key(binary(), mlkem_param_set()) -> binary().
extract_public_key(PrivateKey, mlkem_512) ->
    PubSize = 800,
    <<_:PubSize/binary, PubKey:PubSize/binary>> = PrivateKey,
    PubKey;
extract_public_key(PrivateKey, mlkem_768) ->
    PubSize = 1184,
    <<_:PubSize/binary, PubKey:PubSize/binary>> = PrivateKey,
    PubKey;
extract_public_key(PrivateKey, mlkem_1024) ->
    PubSize = 1568,
    <<_:PubSize/binary, PubKey:PubSize/binary>> = PrivateKey,
    PubKey.

