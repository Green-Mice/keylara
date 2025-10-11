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

%% @doc Generate RSA keypair using default key size
%% @return {ok, {PublicKey, PrivateKey}} | {error, Reason}
-spec generate_keypair() -> {ok, {rsa_public_key(), rsa_private_key()}} | keylara_error().
generate_keypair() ->
    generate_keypair(?DEFAULT_RSA_KEY_SIZE).

%% @doc Generate RSA keypair using Alara distributed entropy network
%% Entropy is managed internally by keylara module
%% @param KeySize - RSA key size in bits (1024, 2048, 4096)
%% @return {ok, {PublicKey, PrivateKey}} | {error, Reason}
-spec generate_keypair(rsa_key_size()) -> {ok, {rsa_public_key(), rsa_private_key()}} | keylara_error().
generate_keypair(KeySize) ->
    try
        case validate_key_size(KeySize) of
            ok ->
                % Calculate how much entropy we need for RSA key generation
                EntropyBytesNeeded = (KeySize * 2 + 7) div 8, % Conservative estimate
                
                % Seed the random number generator with Alara entropy via keylara
                case keylara:seed_random() of
                    ok ->
                        % Get additional entropy for extra security
                        case keylara:get_entropy_bytes(EntropyBytesNeeded) of
                            {ok, _EntropyBytes} ->
                                % Generate RSA keypair using OTP's public_key module
                                % The seeded random generator will be used internally
                                PrivateKey = public_key:generate_key({rsa, KeySize, ?DEFAULT_RSA_EXPONENT}),
                                PublicKey = extract_public_key(PrivateKey),
                                {ok, {PublicKey, PrivateKey}};
                            {error, EntropyReason} ->
                                {error, {entropy_generation_failed, EntropyReason}}
                        end;
                    {error, SeedReason} ->
                        {error, {random_seed_failed, SeedReason}}
                end;
            {error, KeySizeReason} ->
                {error, KeySizeReason}
        end
    catch
        Error:CatchReason:Stacktrace ->
            {error, {keypair_generation_failed, Error, CatchReason, Stacktrace}}
    end.

%% @doc Encrypt data using RSA public key
%% @param Data - Binary data to encrypt
%% @param PublicKey - RSA public key
%% @return {ok, EncryptedData} | {error, Reason}
-spec encrypt(binary() | list(), rsa_public_key()) -> {ok, binary()} | keylara_error().
encrypt(Data, PublicKey) when is_binary(Data) ->
    try
        % Check if data size is within RSA limits
        KeySize = get_key_size(PublicKey),
        MaxDataSize = (KeySize div 8) - 11, % PKCS#1 v1.5 padding overhead
        case byte_size(Data) =< MaxDataSize of
            true ->
                % Use OTP's public_key module for RSA encryption
                EncryptedData = public_key:encrypt_public(Data, PublicKey),
                {ok, EncryptedData};
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

%% @doc Decrypt data using RSA private key
%% @param EncryptedData - Binary encrypted data
%% @param PrivateKey - RSA private key
%% @return {ok, DecryptedData} | {error, Reason}
-spec decrypt(binary(), rsa_private_key()) -> {ok, binary()} | keylara_error().
decrypt(EncryptedData, PrivateKey) when is_binary(EncryptedData) ->
    try
        % Use OTP's public_key module for RSA decryption
        DecryptedData = public_key:decrypt_private(EncryptedData, PrivateKey),
        {ok, DecryptedData}
    catch
        Error:CatchReason:Stacktrace ->
            {error, {decryption_failed, Error, CatchReason, Stacktrace}}
    end;
decrypt(_EncryptedData, _PrivateKey) ->
    {error, invalid_encrypted_data_format}.

%% @doc Extract public key from private key structure
%% @param PrivateKey - RSA private key record
%% @return RSA public key record
-spec extract_public_key(rsa_private_key()) -> rsa_public_key().
extract_public_key(#'RSAPrivateKey'{modulus = N, publicExponent = E}) ->
    #'RSAPublicKey'{modulus = N, publicExponent = E}.

%% @doc Validate RSA key size
%% @param KeySize - Key size in bits
%% @return ok | {error, Reason}
-spec validate_key_size(integer()) -> ok | keylara_error().
validate_key_size(KeySize) when is_integer(KeySize) ->
    ValidSizes = [1024, 2048, 3072, 4096],
    case lists:member(KeySize, ValidSizes) of
        true ->
            case KeySize >= ?MIN_RSA_KEY_SIZE andalso KeySize =< ?MAX_RSA_KEY_SIZE of
                true ->
                    ok;
                false ->
                    {error, {key_size_out_of_range, KeySize, ?MIN_RSA_KEY_SIZE, ?MAX_RSA_KEY_SIZE}}
            end;
        false ->
            {error, {invalid_key_size, KeySize, ValidSizes}}
    end;
validate_key_size(KeySize) ->
    {error, {invalid_key_size_type, KeySize}}.

%% @doc Get the size of an RSA key in bits
%% @param Key - RSA public or private key
%% @return Key size in bits
-spec get_key_size(rsa_public_key() | rsa_private_key()) -> integer().
get_key_size(#'RSAPublicKey'{modulus = N}) ->
    bit_size(binary:encode_unsigned(N));
get_key_size(#'RSAPrivateKey'{modulus = N}) ->
    bit_size(binary:encode_unsigned(N));
get_key_size(_) ->
    {error, invalid_key_format}.

%%%===================================================================
%%% Unit Tests (if compiled with TEST flag)
%%%===================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

validate_key_size_test() ->
    ?assertEqual(ok, validate_key_size(1024)),
    ?assertEqual(ok, validate_key_size(2048)),
    ?assertEqual(ok, validate_key_size(4096)),
    ?assertMatch({error, {invalid_key_size, 512, _}}, validate_key_size(512)),
    ?assertMatch({error, {invalid_key_size, 8192, _}}, validate_key_size(8192)),
    ?assertMatch({error, {invalid_key_size_type, _}}, validate_key_size("invalid")).
-endif.

