%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Unit tests for the KeyLara SLH-DSA post-quantum signature module.
%%% Updated for centralized entropy management.
%%% Covers:
%%% - Keypair generation (with distributed entropy)
%%% - Format and size validation
%%% - Error handling
%%% @end
%%%-------------------------------------------------------------------

-module(keylara_slhdsa_tests).

-include_lib("eunit/include/eunit.hrl").

%% Redefinition of macros used for parameter sets
-define(SLH_DSA_SHA2_128S, slh_dsa_sha2_128s).
-define(SLH_DSA_SHA2_128F, slh_dsa_sha2_128f).
-define(SLH_DSA_SHA2_192S, slh_dsa_sha2_192s).
-define(SLH_DSA_SHA2_192F, slh_dsa_sha2_192f).
-define(SLH_DSA_SHA2_256S, slh_dsa_sha2_256s).
-define(SLH_DSA_SHA2_256F, slh_dsa_sha2_256f).

%% Export test runner (optional)
-export([run_all_tests/0]).

%% Main EUnit generator using setup and cleanup
keylara_slhdsa_test_() ->
    {setup,
     fun setup_test_environment/0,
     fun cleanup_test_environment/1,
     [
         {timeout, 30, fun test_keypair_generation/0},
         {timeout, 30, fun test_invalid_parameters/0},
         {timeout, 30, fun test_format_validations/0},
         {timeout, 30, fun test_signature_format_errors/0},
         {timeout, 30, fun test_parameter_sizes/0},
         {timeout, 30, fun test_different_security_levels/0}
     ]}.

%%%--------------------
%%% Setup/cleanup
%%%--------------------
setup_test_environment() ->
    io:format("Setting up SLH-DSA test environment...~n"),
    application:start(crypto),
    application:start(public_key),
    keylara:start(),
    io:format("SLH-DSA test environment ready.~n"),
    ok.

cleanup_test_environment(_Ctx) ->
    io:format("Cleaning up SLH-DSA test environment.~n"),
    keylara:stop(),
    application:stop(public_key),
    application:stop(crypto),
    ok.

%%%--------------------------
%%% Test: Keypair generation
%%%--------------------------
test_keypair_generation() ->
    io:format("Testing SLH-DSA keypair generation...~n"),

    % Test with SLH-DSA-SHA2-128s
    Result = keylara_slhdsa:generate_keypair(?SLH_DSA_SHA2_128S),
    ?assertMatch({ok, {_PublicKey, _PrivateKey}}, Result),

    % Extract and verify keys
    {ok, {PublicKey, PrivateKey}} = Result,
    ?assert(is_binary(PublicKey)),
    ?assert(is_binary(PrivateKey)),
    ?assertEqual(32, byte_size(PublicKey)),
    ?assertEqual(64, byte_size(PrivateKey)),

    io:format("✓ Keypair generation test passed~n").

%%%--------------------------
%%% Test: Different security levels
%%%--------------------------
test_different_security_levels() ->
    io:format("Testing different SLH-DSA security levels...~n"),

    % Test SLH-DSA-SHA2-128s (small)
    {ok, {PubKey128s, PrivKey128s}} = keylara_slhdsa:generate_keypair(?SLH_DSA_SHA2_128S),
    ?assertEqual(32, byte_size(PubKey128s)),
    ?assertEqual(64, byte_size(PrivKey128s)),
    io:format("✓ SLH-DSA-SHA2-128s test passed~n"),

    % Test SLH-DSA-SHA2-128f (fast)
    {ok, {PubKey128f, PrivKey128f}} = keylara_slhdsa:generate_keypair(?SLH_DSA_SHA2_128F),
    ?assertEqual(32, byte_size(PubKey128f)),
    ?assertEqual(64, byte_size(PrivKey128f)),
    io:format("✓ SLH-DSA-SHA2-128f test passed~n"),

    % Test SLH-DSA-SHA2-192s
    {ok, {PubKey192s, PrivKey192s}} = keylara_slhdsa:generate_keypair(?SLH_DSA_SHA2_192S),
    ?assertEqual(48, byte_size(PubKey192s)),
    ?assertEqual(96, byte_size(PrivKey192s)),
    io:format("✓ SLH-DSA-SHA2-192s test passed~n"),

    % Test SLH-DSA-SHA2-256s
    {ok, {PubKey256s, PrivKey256s}} = keylara_slhdsa:generate_keypair(?SLH_DSA_SHA2_256S),
    ?assertEqual(64, byte_size(PubKey256s)),
    ?assertEqual(128, byte_size(PrivKey256s)),
    io:format("✓ SLH-DSA-SHA2-256s test passed~n"),

    io:format("✓ Different security levels test passed~n").

%%%--------------------------------------
%%% Test: Parameter and format validations
%%%--------------------------------------
test_format_validations() ->
    io:format("Testing format validations...~n"),

    % Known valid sizes should pass
    ?assertEqual(ok, keylara_slhdsa:validate_public_key(crypto:strong_rand_bytes(32), ?SLH_DSA_SHA2_128S)),
    ?assertEqual(ok, keylara_slhdsa:validate_private_key(crypto:strong_rand_bytes(64), ?SLH_DSA_SHA2_128S)),
    ?assertEqual(ok, keylara_slhdsa:validate_signature(crypto:strong_rand_bytes(7856), ?SLH_DSA_SHA2_128S)),
    io:format("✓ Valid sizes pass validation~n"),

    % Invalid sizes should raise errors
    ?assertMatch({error, _}, keylara_slhdsa:validate_public_key(crypto:strong_rand_bytes(10), ?SLH_DSA_SHA2_128S)),
    ?assertMatch({error, _}, keylara_slhdsa:validate_private_key(crypto:strong_rand_bytes(10), ?SLH_DSA_SHA2_128S)),
    ?assertMatch({error, _}, keylara_slhdsa:validate_signature(crypto:strong_rand_bytes(10), ?SLH_DSA_SHA2_128S)),
    io:format("✓ Invalid sizes rejected~n"),

    io:format("✓ Format validations test passed~n").

%%%--------------------------------------
%%% Test: Invalid parameter set handling
%%%--------------------------------------
test_invalid_parameters() ->
    io:format("Testing invalid parameters...~n"),

    % Invalid parameter set
    ?assertMatch({error, {invalid_parameter_set, _}}, 
                 keylara_slhdsa:generate_keypair(badparam)),
    ?assertMatch({error, {invalid_parameter_set, _}}, 
                 keylara_slhdsa:get_parameter_sizes(badparam)),
    ?assertMatch({error, {invalid_parameter_set, _}}, 
                 keylara_slhdsa:validate_public_key(<<1,2,3>>, badparam)),
    
    io:format("✓ Invalid parameters test passed~n").

%%%--------------------------------------
%%% Test: Signature and key format errors
%%%--------------------------------------
test_signature_format_errors() ->
    io:format("Testing signature and key format errors...~n"),

    % Passing non-binary to validate_signature must raise error
    ?assertMatch({error, invalid_signature_format}, 
                 keylara_slhdsa:validate_signature(notabinary, ?SLH_DSA_SHA2_128S)),
    
    % Non-binaries to public/private key validations raise errors
    ?assertMatch({error, invalid_public_key_format}, 
                 keylara_slhdsa:validate_public_key([1,2,3], ?SLH_DSA_SHA2_128S)),
    ?assertMatch({error, invalid_private_key_format}, 
                 keylara_slhdsa:validate_private_key(#{map=>not_valid}, ?SLH_DSA_SHA2_128S)),
    
    io:format("✓ Signature and key format errors test passed~n").

%%%--------------------------------------
%%% Test: Parameter sizes
%%%--------------------------------------
test_parameter_sizes() ->
    io:format("Testing parameter sizes...~n"),

    % Test SLH-DSA-SHA2-128s parameters
    {ok, Params128s} = keylara_slhdsa:get_parameter_sizes(?SLH_DSA_SHA2_128S),
    ?assertEqual(32, maps:get(public_key_size, Params128s)),
    ?assertEqual(64, maps:get(private_key_size, Params128s)),
    ?assertEqual(7856, maps:get(signature_size, Params128s)),
    io:format("✓ SLH-DSA-SHA2-128s parameters correct~n"),

    % Test SLH-DSA-SHA2-192s parameters
    {ok, Params192s} = keylara_slhdsa:get_parameter_sizes(?SLH_DSA_SHA2_192S),
    ?assertEqual(48, maps:get(public_key_size, Params192s)),
    ?assertEqual(96, maps:get(private_key_size, Params192s)),
    ?assertEqual(16272, maps:get(signature_size, Params192s)),
    io:format("✓ SLH-DSA-SHA2-192s parameters correct~n"),

    % Test SLH-DSA-SHA2-256s parameters
    {ok, Params256s} = keylara_slhdsa:get_parameter_sizes(?SLH_DSA_SHA2_256S),
    ?assertEqual(64, maps:get(public_key_size, Params256s)),
    ?assertEqual(128, maps:get(private_key_size, Params256s)),
    ?assertEqual(29776, maps:get(signature_size, Params256s)),
    io:format("✓ SLH-DSA-SHA2-256s parameters correct~n"),

    io:format("✓ Parameter sizes test passed~n").

%%%-------------------------------------------------------------------
%%% Test runner for manual execution (optional)
%%%-------------------------------------------------------------------
run_all_tests() ->
    io:format("~n=== Running SLH-DSA Complete Test Suite ===~n"),
    eunit:test(?MODULE, [verbose]).

