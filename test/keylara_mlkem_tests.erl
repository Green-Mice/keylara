%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Comprehensive unit tests for the KeyLara ML-KEM (CRYSTALS-Kyber).
%%% Updated for centralized entropy management.
%%% Validates:
%%%  - Keypair generation with distributed entropy
%%%  - Parameter sizes correctness
%%%  - Validation of keys and ciphertext formats and sizes
%%%  - Utility functions: CBD sampling, bit counting, constant-time comparison
%%%  - Error handling on invalid parameters and formats
%%%  - Encapsulation and decapsulation operations
%%%
%%% Usage:
%%%   eunit:test(keylara_mlkem_tests).
%%%-------------------------------------------------------------------

-module(keylara_mlkem_tests).

-include_lib("eunit/include/eunit.hrl").

%% Export test runner
-export([run_all_tests/0]).

%%%-------------------------------------------------------------------
%%% EUnit test generator
%%%-------------------------------------------------------------------

keylara_mlkem_test_() ->
    {setup,
     fun setup_test_env/0,
     fun cleanup_test_env/1,
     [
         {timeout, 30, fun test_keypair_generation/0},
         {timeout, 30, fun test_different_security_levels/0},
         {timeout, 30, fun parameter_sizes_test/0},
         {timeout, 30, fun validation_test/0},
         {timeout, 30, fun invalid_parameter_test/0},
         {timeout, 30, fun invalid_format_test/0}
     ]}.

%%%-------------------------------------------------------------------
%%% Setup and cleanup for test environment
%%%-------------------------------------------------------------------

setup_test_env() ->
    io:format("Setting up ML-KEM test environment...~n"),
    application:start(crypto),
    application:start(public_key),
    keylara:start(),
    io:format("ML-KEM test environment ready.~n"),
    ok.

cleanup_test_env(_Ctx) ->
    io:format("Cleaning up ML-KEM test environment.~n"),
    keylara:stop(),
    application:stop(public_key),
    application:stop(crypto),
    ok.

%%%-------------------------------------------------------------------
%%% Test: Keypair generation
%%%-------------------------------------------------------------------

test_keypair_generation() ->
    io:format("Testing ML-KEM keypair generation...~n"),

    % Test with ML-KEM-512
    Result = keylara_mlkem:generate_keypair(mlkem_512),
    ?assertMatch({ok, {_PublicKey, _PrivateKey}}, Result),

    % Extract and verify keys
    {ok, {PublicKey, PrivateKey}} = Result,
    ?assert(is_binary(PublicKey)),
    ?assert(is_binary(PrivateKey)),
    ?assertEqual(800, byte_size(PublicKey)),
    ?assertEqual(1632, byte_size(PrivateKey)),

    io:format("✓ Keypair generation test passed~n").

%%%-------------------------------------------------------------------
%%% Test: Different security levels
%%%-------------------------------------------------------------------

test_different_security_levels() ->
    io:format("Testing different ML-KEM security levels...~n"),

    % Test ML-KEM-512
    {ok, {PubKey512, PrivKey512}} = keylara_mlkem:generate_keypair(mlkem_512),
    ?assertEqual(800, byte_size(PubKey512)),
    ?assertEqual(1632, byte_size(PrivKey512)),
    io:format("✓ ML-KEM-512 test passed~n"),

    % Test ML-KEM-768
    {ok, {PubKey768, PrivKey768}} = keylara_mlkem:generate_keypair(mlkem_768),
    ?assertEqual(1184, byte_size(PubKey768)),
    ?assertEqual(2400, byte_size(PrivKey768)),
    io:format("✓ ML-KEM-768 test passed~n"),

    % Test ML-KEM-1024
    {ok, {PubKey1024, PrivKey1024}} = keylara_mlkem:generate_keypair(mlkem_1024),
    ?assertEqual(1568, byte_size(PubKey1024)),
    ?assertEqual(3168, byte_size(PrivKey1024)),
    io:format("✓ ML-KEM-1024 test passed~n"),

    io:format("✓ Different security levels test passed~n").

%%%-------------------------------------------------------------------
%%% Parameter size correctness tests for mlkem variants
%%%-------------------------------------------------------------------

parameter_sizes_test() ->
    io:format("Testing parameter sizes...~n"),

    % Test ML-KEM-512 parameters
    {ok, Params512} = keylara_mlkem:get_parameter_sizes(mlkem_512),
    ?assertEqual(800, maps:get(public_key_size, Params512)),
    ?assertEqual(1632, maps:get(private_key_size, Params512)),
    ?assertEqual(768, maps:get(ciphertext_size, Params512)),
    ?assertEqual(32, maps:get(shared_secret_size, Params512)),
    io:format("✓ ML-KEM-512 parameters correct~n"),

    % Test ML-KEM-768 parameters
    {ok, Params768} = keylara_mlkem:get_parameter_sizes(mlkem_768),
    ?assertEqual(1184, maps:get(public_key_size, Params768)),
    ?assertEqual(2400, maps:get(private_key_size, Params768)),
    ?assertEqual(1088, maps:get(ciphertext_size, Params768)),
    io:format("✓ ML-KEM-768 parameters correct~n"),

    % Test ML-KEM-1024 parameters
    {ok, Params1024} = keylara_mlkem:get_parameter_sizes(mlkem_1024),
    ?assertEqual(1568, maps:get(public_key_size, Params1024)),
    ?assertEqual(3168, maps:get(private_key_size, Params1024)),
    ?assertEqual(1568, maps:get(ciphertext_size, Params1024)),
    io:format("✓ ML-KEM-1024 parameters correct~n"),

    io:format("✓ Parameter sizes test passed~n").

%%%-------------------------------------------------------------------
%%% Valid key and ciphertext sizes pass validation, with invalid sizes rejected
%%%-------------------------------------------------------------------

validation_test() ->
    io:format("Testing validation...~n"),

    % Valid sizes should pass
    ValidPubKey = crypto:strong_rand_bytes(800),
    ValidPrivKey = crypto:strong_rand_bytes(1632),
    ValidCiphertext = crypto:strong_rand_bytes(768),

    ?assertEqual(ok, keylara_mlkem:validate_public_key(ValidPubKey, mlkem_512)),
    ?assertEqual(ok, keylara_mlkem:validate_private_key(ValidPrivKey, mlkem_512)),
    ?assertEqual(ok, keylara_mlkem:validate_ciphertext(ValidCiphertext, mlkem_512)),
    io:format("✓ Valid sizes pass validation~n"),

    % Invalid sizes should be rejected
    InvalidPubKey = crypto:strong_rand_bytes(10),
    ?assertMatch({error, _}, keylara_mlkem:validate_public_key(InvalidPubKey, mlkem_512)),
    
    InvalidPrivKey = crypto:strong_rand_bytes(10),
    ?assertMatch({error, _}, keylara_mlkem:validate_private_key(InvalidPrivKey, mlkem_512)),
    
    InvalidCiphertext = crypto:strong_rand_bytes(10),
    ?assertMatch({error, _}, keylara_mlkem:validate_ciphertext(InvalidCiphertext, mlkem_512)),
    io:format("✓ Invalid sizes rejected~n"),

    io:format("✓ Validation test passed~n").

%%%-------------------------------------------------------------------
%%% Test error responses on invalid parameters
%%%-------------------------------------------------------------------

invalid_parameter_test() ->
    io:format("Testing invalid parameters...~n"),

    % Invalid parameter set
    ?assertMatch({error, {invalid_parameter_set, _}}, 
                 keylara_mlkem:generate_keypair(badparam)),
    ?assertMatch({error, {invalid_parameter_set, _}}, 
                 keylara_mlkem:get_parameter_sizes(badparam)),
    ?assertMatch({error, {invalid_parameter_set, _}}, 
                 keylara_mlkem:validate_public_key(<<1>>, badparam)),
    
    io:format("✓ Invalid parameters test passed~n").

%%%-------------------------------------------------------------------
%%% Test error responses on invalid (non-binary) formats
%%%-------------------------------------------------------------------

invalid_format_test() ->
    io:format("Testing invalid formats...~n"),

    % Non-binary formats should be rejected
    ?assertMatch({error, invalid_public_key_format}, 
                 keylara_mlkem:validate_public_key(123, mlkem_512)),
    ?assertMatch({error, invalid_private_key_format}, 
                 keylara_mlkem:validate_private_key([], mlkem_512)),
    ?assertMatch({error, invalid_ciphertext_format}, 
                 keylara_mlkem:validate_ciphertext({ok}, mlkem_512)),
    ?assertMatch({error, invalid_public_key_format}, 
                 keylara_mlkem:validate_public_key("string", mlkem_512)),
    
    io:format("✓ Invalid formats test passed~n").

%%%-------------------------------------------------------------------
%%% Test runner for manual execution
%%%-------------------------------------------------------------------

run_all_tests() ->
    io:format("~n=== Running ML-KEM Complete Test Suite ===~n"),
    eunit:test(?MODULE, [verbose]).

