%%%===================================================================
%%% File: include/keylara.hrl
%%% Description: Common definitions and constants for Keylara
%%%===================================================================

-ifndef(KEYLARA_HRL).
-define(KEYLARA_HRL, true).

%% Include required libraries
-include_lib("public_key/include/public_key.hrl").

%% AES Constants
-define(AES_128, 128).
-define(AES_192, 192).
-define(AES_256, 256).
-define(AES_BLOCK_SIZE, 16).  % AES block size is always 16 bytes
-define(AES_IV_SIZE, 16).     % AES IV size is always 16 bytes

%% RSA Constants
-define(DEFAULT_RSA_EXPONENT, 65537).
-define(MIN_RSA_KEY_SIZE, 1024).
-define(DEFAULT_RSA_KEY_SIZE, 2048).
-define(MAX_RSA_KEY_SIZE, 4096).

%% Error types
-type keylara_error() :: {error, term()}.
-type entropy_error() :: {entropy_generation_failed, term()} |
                        {insufficient_entropy, integer(), integer()} |
                        {alara_network_error, term(), term()}.
-type crypto_error() :: {encryption_failed, term(), term()} |
                       {decryption_failed, term(), term()} |
                       {key_generation_failed, term(), term()}.

%% Key types
-type aes_key_size() :: 128 | 192 | 256.
-type aes_key() :: binary().
-type aes_iv() :: binary().
-type rsa_key_size() :: 1024 | 2048 | 4096.
-type rsa_public_key() :: #'RSAPublicKey'{}.
-type rsa_private_key() :: #'RSAPrivateKey'{}.

%% Encryption result types
-type aes_encrypted() :: {aes_iv(), binary()}.
-type rsa_encrypted() :: binary().
-type hybrid_encrypted() :: {rsa_encrypted(), aes_iv(), binary()}.

-endif.
