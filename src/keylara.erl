%%%===================================================================
%%% File: src/keylara.erl
%%% Description: Main Keylara cryptographic module (simplified)
%%%===================================================================
-module(keylara).

-export([
    % RSA operations
    generate_rsa_keypair/1,
    generate_rsa_keypair/2,
    rsa_encrypt/2,
    rsa_decrypt/2,
    
    % AES operations
    generate_aes_key/2,
    aes_encrypt/2,
    aes_decrypt/3,
    
    % Utility functions
    start/0,
    stop/0,
    get_version/0
]).

-include("keylara.hrl").

%%%===================================================================
%%% Public API - RSA Operations
%%%===================================================================

%% @doc Generate RSA keypair using default key size (2048 bits)
%% @param NetPid - Process ID of the Alara network
%% @return {ok, {PublicKey, PrivateKey}} | {error, Reason}
-spec generate_rsa_keypair(pid()) -> {ok, {rsa_public_key(), rsa_private_key()}} | keylara_error().
generate_rsa_keypair(NetPid) ->
    keylara_rsa:generate_keypair(NetPid).

%% @doc Generate RSA keypair with specified key size
%% @param NetPid - Process ID of the Alara network
%% @param KeySize - RSA key size in bits (1024, 2048, 3072, 4096)
%% @return {ok, {PublicKey, PrivateKey}} | {error, Reason}
-spec generate_rsa_keypair(pid(), rsa_key_size()) -> {ok, {rsa_public_key(), rsa_private_key()}} | keylara_error().
generate_rsa_keypair(NetPid, KeySize) ->
    keylara_rsa:generate_keypair(NetPid, KeySize).

%% @doc Encrypt data using RSA public key
%% @param Data - Data to encrypt (binary or string)
%% @param PublicKey - RSA public key
%% @return {ok, EncryptedData} | {error, Reason}
-spec rsa_encrypt(binary() | list(), rsa_public_key()) -> {ok, binary()} | keylara_error().
rsa_encrypt(Data, PublicKey) ->
    keylara_rsa:encrypt(Data, PublicKey).

%% @doc Decrypt data using RSA private key
%% @param EncryptedData - Encrypted data to decrypt
%% @param PrivateKey - RSA private key
%% @return {ok, DecryptedData} | {error, Reason}
-spec rsa_decrypt(binary(), rsa_private_key()) -> {ok, binary()} | keylara_error().
rsa_decrypt(EncryptedData, PrivateKey) ->
    keylara_rsa:decrypt(EncryptedData, PrivateKey).

%%%===================================================================
%%% Public API - AES Operations
%%%===================================================================

%% @doc Generate AES key using Alara entropy
%% @param NetPid - Process ID of the Alara network
%% @param KeySize - AES key size (128, 192, or 256 bits)
%% @return {ok, AESKey} | {error, Reason}
-spec generate_aes_key(pid(), aes_key_size()) -> {ok, aes_key()} | keylara_error().
generate_aes_key(NetPid, KeySize) ->
    keylara_entropy:generate_aes_key(NetPid, KeySize).

%% @doc Encrypt data using AES (assumes you have keylara_aes module)
%% @param Data - Data to encrypt
%% @param Key - AES key
%% @return {ok, {IV, EncryptedData}} | {error, Reason}
-spec aes_encrypt(binary(), aes_key()) -> {ok, {aes_iv(), binary()}} | keylara_error().
aes_encrypt(Data, Key) ->
    keylara_aes:encrypt(Data, Key).

%% @doc Decrypt data using AES (assumes you have keylara_aes module)
%% @param EncryptedData - Encrypted data
%% @param Key - AES key
%% @param IV - Initialization vector
%% @return {ok, DecryptedData} | {error, Reason}
-spec aes_decrypt(binary(), aes_key(), aes_iv()) -> {ok, binary()} | keylara_error().
aes_decrypt(EncryptedData, Key, IV) ->
    keylara_aes:decrypt(EncryptedData, Key, IV).

%%%===================================================================
%%% Utility Functions
%%%===================================================================

%% @doc Start the Keylara application
%% @return ok | {error, Reason}
-spec start() -> ok | {error, term()}.
start() ->
    % Start required applications
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),
    % Start Alara if available
    case application:ensure_all_started(alara) of
        {ok, _} ->
            io:format("Keylara started successfully with Alara network~n"),
            ok;
        {error, {alara, _}} ->
            io:format("Keylara started in standalone mode (Alara not available)~n"),
            ok;
        {error, Reason} ->
            {error, {failed_to_start_dependencies, Reason}}
    end.

%% @doc Stop the Keylara application
%% @return ok
-spec stop() -> ok.
stop() ->
    application:stop(alara),
    io:format("Keylara stopped~n"),
    ok.

%% @doc Get Keylara version
%% @return Version string
-spec get_version() -> string().
get_version() ->
    "1.0.0-simplified".

%%%===================================================================
%%% Unit Tests (if compiled with TEST flag)
%%%===================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

start_stop_test() ->
    ?assertEqual(ok, start()),
    ?assertEqual(ok, stop()).

get_version_test() ->
    Version = get_version(),
    ?assert(is_list(Version)),
    ?assert(length(Version) > 0).

-endif.
