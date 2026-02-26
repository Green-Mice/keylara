%%%===================================================================
%%% Description: RSA encryption/decryption functions
%%% Using centralized entropy management from keylara module
%%%===================================================================
-module(keylara_rsa).

-export([
    generate_keypair/0,
    generate_keypair/1,
    encrypt/2,
    decrypt/2,
    extract_public_key/1,
    validate_key_size/1,
    get_key_size/1
]).

-include_lib("public_key/include/public_key.hrl").
-include("keylara.hrl").

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Generate an RSA keypair using the default key size.
%% @return {ok, {PublicKey, PrivateKey}} | {error, Reason}
-spec generate_keypair() -> {ok, {rsa_public_key(), rsa_private_key()}} | keylara_error().
generate_keypair() ->
    generate_keypair(?DEFAULT_RSA_KEY_SIZE).

%% @doc Generate an RSA keypair of the given size.
%%
%% Entropy is fetched from the ALARA pool via `keylara:get_entropy_bytes/1`
%% as a confirmation that the entropy system is healthy before delegating
%% the actual key generation to OTP's `public_key` module.
%%
%% Note: `public_key:generate_key/1` calls `crypto` internally.  There
%% is no mechanism in OTP to inject external entropy into that call, so
%% seeding `rand` (the old approach) had no effect on RSA key generation.
%% The entropy check here serves as a liveness gate only.
%%
%% @param KeySize - RSA key size in bits (1024, 2048, 3072, or 4096)
%% @return {ok, {PublicKey, PrivateKey}} | {error, Reason}
-spec generate_keypair(rsa_key_size()) ->
    {ok, {rsa_public_key(), rsa_private_key()}} | keylara_error().
generate_keypair(KeySize) ->
    try
        case validate_key_size(KeySize) of
            ok ->
                %% Verify the entropy pool is reachable before proceeding.
                %% (KeySize * 2 + 7) div 8 is a conservative byte estimate
                %% proportional to the key size.
                EntropyBytes = (KeySize * 2 + 7) div 8,
                case keylara:get_entropy_bytes(EntropyBytes) of
                    {ok, _} ->
                        %% public_key:generate_key uses crypto:strong_rand_bytes
                        %% internally — no external seeding required or possible.
                        PrivateKey = public_key:generate_key(
                            {rsa, KeySize, ?DEFAULT_RSA_EXPONENT}
                        ),
                        PublicKey = extract_public_key(PrivateKey),
                        {ok, {PublicKey, PrivateKey}};
                    {error, EntropyReason} ->
                        {error, {random_seed_failed, EntropyReason}}
                end;
            {error, KeySizeReason} ->
                {error, KeySizeReason}
        end
    catch
        Error:CatchReason:Stacktrace ->
            {error, {keypair_generation_failed, Error, CatchReason, Stacktrace}}
    end.

%% @doc Encrypt data using an RSA public key (PKCS#1 v1.5).
%% @param Data       - Binary data to encrypt
%% @param PublicKey  - RSA public key
%% @return {ok, EncryptedData} | {error, Reason}
-spec encrypt(binary() | list(), rsa_public_key()) ->
    {ok, binary()} | keylara_error().
encrypt(Data, PublicKey) when is_binary(Data) ->
    try
        KeySize    = get_key_size(PublicKey),
        MaxDataSize = (KeySize div 8) - 11, % PKCS#1 v1.5 overhead
        case byte_size(Data) =< MaxDataSize of
            true ->
                {ok, public_key:encrypt_public(Data, PublicKey)};
            false ->
                {error, {data_too_large, byte_size(Data), MaxDataSize}}
        end
    catch
        Error:CatchReason:Stacktrace ->
            {error, {encryption_failed, Error, CatchReason, Stacktrace}}
    end;
encrypt(Data, PublicKey) when is_list(Data) ->
    encrypt(list_to_binary(Data), PublicKey);
encrypt(_Data, _PublicKey) ->
    {error, invalid_data_format}.

%% @doc Decrypt data using an RSA private key.
%% @param EncryptedData - Binary encrypted data
%% @param PrivateKey    - RSA private key
%% @return {ok, DecryptedData} | {error, Reason}
-spec decrypt(binary(), rsa_private_key()) ->
    {ok, binary()} | keylara_error().
decrypt(EncryptedData, PrivateKey) when is_binary(EncryptedData) ->
    try
        {ok, public_key:decrypt_private(EncryptedData, PrivateKey)}
    catch
        Error:CatchReason:Stacktrace ->
            {error, {decryption_failed, Error, CatchReason, Stacktrace}}
    end;
decrypt(_EncryptedData, _PrivateKey) ->
    {error, invalid_encrypted_data_format}.

%% @doc Extract the public key from a private key record.
-spec extract_public_key(rsa_private_key()) -> rsa_public_key().
extract_public_key(#'RSAPrivateKey'{modulus = N, publicExponent = E}) ->
    #'RSAPublicKey'{modulus = N, publicExponent = E}.

%% @doc Validate that `KeySize` is a supported RSA key size.
-spec validate_key_size(integer()) -> ok | keylara_error().
validate_key_size(KeySize) when is_integer(KeySize) ->
    ValidSizes = [1024, 2048, 3072, 4096],
    case lists:member(KeySize, ValidSizes) of
        true ->
            case KeySize >= ?MIN_RSA_KEY_SIZE andalso KeySize =< ?MAX_RSA_KEY_SIZE of
                true  -> ok;
                false -> {error, {key_size_out_of_range, KeySize,
                                  ?MIN_RSA_KEY_SIZE, ?MAX_RSA_KEY_SIZE}}
            end;
        false ->
            {error, {invalid_key_size, KeySize, ValidSizes}}
    end;
validate_key_size(KeySize) ->
    {error, {invalid_key_size_type, KeySize}}.

%% @doc Return the size of an RSA key in bits.
-spec get_key_size(rsa_public_key() | rsa_private_key()) ->
    pos_integer() | keylara_error().
get_key_size(#'RSAPublicKey'{modulus = N}) ->
    bit_size(binary:encode_unsigned(N));
get_key_size(#'RSAPrivateKey'{modulus = N}) ->
    bit_size(binary:encode_unsigned(N));
get_key_size(_) ->
    {error, invalid_key_format}.

%%%===================================================================
%%% Unit Tests
%%%===================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

validate_key_size_test() ->
    ?assertEqual(ok, validate_key_size(1024)),
    ?assertEqual(ok, validate_key_size(2048)),
    ?assertEqual(ok, validate_key_size(4096)),
    ?assertMatch({error, {invalid_key_size, 512,  _}}, validate_key_size(512)),
    ?assertMatch({error, {invalid_key_size, 8192, _}}, validate_key_size(8192)),
    ?assertMatch({error, {invalid_key_size_type, _}},  validate_key_size("bad")).
-endif.
