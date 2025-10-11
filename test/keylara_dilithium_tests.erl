%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Unit tests for the KeyLara Dilithium post-quantum signature module.
%%% Updated for centralized entropy management.
%%% Covers:
%%% - Keypair generation (with distributed entropy)
%%% - Format and size validation
%%% - Error handling
%%% @end
%%%-------------------------------------------------------------------

-module(keylara_dilithium_tests).

-include_lib("eunit/include/eunit.hrl").

%% Exported test runner (optional)
-export([run_all_tests/0]).

%% Main EUnit generator
keylara_dilithium_test_() ->
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
    io:format("Setting up Dilithium test environment...~n"),
    application:start(crypto),
    application:start(public_key),
    keylara:start(),
    io:format("Dilithium test environment ready.~n"),
    ok.

cleanup_test_environment(_Ctx) ->
    io:format("Cleaning up Dilithium test environment.~n"),
    keylara:stop(),
    application:stop(public_key),
    application:stop(crypto),
    ok.

%%%--------------------------
%%% Test: Keypair generation
%%%--------------------------
test_keypair_generation() ->
    io:format("Testing Dilithium keypair generation...~n"),

    % Test with Dilithium-2 (security level 2)
    Result = keylara_dilithium:generate_keypair(dilithium_2),
    ?assertMatch({ok, {_PublicKey, _PrivateKey}}, Result),

    % Extract and verify keys
    {ok, {PublicKey, PrivateKey}} = Result,
    ?assert(is_binary(PublicKey)),
    ?assert(is_binary(PrivateKey)),
    ?assertEqual(1312, byte_size(PublicKey)),
    ?assertEqual(2528, byte_size(PrivateKey)),

    io:format("✓ Keypair generation test passed~n").

%%%--------------------------
%%% Test: Different security levels
%%%--------------------------
test_different_security_levels() ->
    io:format("Testing different Dilithium security levels...~n"),

    % Test Dilithium-2
    {ok, {PubKey2, PrivKey2}} = keylara_dilithium:generate_keypair(dilithium_2),
    ?assertEqual(1312, byte_size(PubKey2)),
    ?assertEqual(2528, byte_size(PrivKey2)),
    io:format("✓ Dilithium-2 test passed~n"),

    % Test Dilithium-3
    {ok, {PubKey3, PrivKey3}} = keylara_dilithium:generate_keypair(dilithium_3),
    ?assertEqual(1952, byte_size(PubKey3)),
    ?assertEqual(4032, byte_size(PrivKey3)),
    io:format("✓ Dilithium-3 test passed~n"),

    % Test Dilithium-5
    {ok, {PubKey5, PrivKey5}} = keylara_dilithium:generate_keypair(dilithium_5),
    ?assertEqual(2592, byte_size(PubKey5)),
    ?assertEqual(4864, byte_size(PrivKey5)),
    io:format("✓ Dilithium-5 test passed~n"),

    io:format("✓ Different security levels test passed~n").

%%%--------------------------------------
%%% Test: Parameter/Format Validations
%%%--------------------------------------
test_format_validations() ->
    io:format("Testing format validations...~n"),

    % Verify known good sizes pass
    ?assertEqual(ok, keylara_dilithium:validate_public_key(crypto:strong_rand_bytes(1312), dilithium_2)),
    ?assertEqual(ok, keylara_dilithium:validate_private_key(crypto:strong_rand_bytes(2528), dilithium_2)),
    ?assertEqual(ok, keylara_dilithium:validate_signature(crypto:strong_rand_bytes(2420), dilithium_2)),
    io:format("✓ Valid sizes pass validation~n"),

    % Wrong sizes should be errors
    ?assertMatch({error, _}, keylara_dilithium:validate_public_key(crypto:strong_rand_bytes(100), dilithium_2)),
    ?assertMatch({error, _}, keylara_dilithium:validate_private_key(crypto:strong_rand_bytes(99), dilithium_2)),
    ?assertMatch({error, _}, keylara_dilithium:validate_signature(crypto:strong_rand_bytes(1), dilithium_2)),
    io:format("✓ Invalid sizes rejected~n"),

    io:format("✓ Format validations test passed~n").

%%%--------------------------------------
%%% Test: Invalid parameter error handling
%%%--------------------------------------
test_invalid_parameters() ->
    io:format("Testing invalid parameters...~n"),

    % Invalid parameter set
    ?assertMatch({error, {invalid_parameter_set, _}}, 
                 keylara_dilithium:generate_keypair(badparam)),
    ?assertMatch({error, {invalid_parameter_set, _}}, 
                 keylara_dilithium:get_parameter_sizes(badparam)),
    ?assertMatch({error, {invalid_parameter_set, _}}, 
                 keylara_dilithium:validate_public_key(<<1,2,3>>, badparam)),
    
    io:format("✓ Invalid parameters test passed~n").

%%%--------------------------------------
%%% Test: Signature format validation
%%%--------------------------------------
test_signature_format_errors() ->
    io:format("Testing signature format errors...~n"),

    % Not a binary
    ?assertMatch({error, invalid_signature_format}, 
                 keylara_dilithium:validate_signature(notabinary, dilithium_2)),
    ?assertMatch({error, invalid_public_key_format}, 
                 keylara_dilithium:validate_public_key([1,2,3], dilithium_2)),
    ?assertMatch({error, invalid_private_key_format}, 
                 keylara_dilithium:validate_private_key({tuple}, dilithium_2)),
    
    io:format("✓ Signature format errors test passed~n").

%%%--------------------------------------
%%% Test: Parameter sizes
%%%--------------------------------------
test_parameter_sizes() ->
    io:format("Testing parameter sizes...~n"),

    % Test Dilithium-2 parameters
    {ok, Params2} = keylara_dilithium:get_parameter_sizes(dilithium_2),
    ?assertEqual(1312, maps:get(public_key_size, Params2)),
    ?assertEqual(2528, maps:get(private_key_size, Params2)),
    ?assertEqual(2420, maps:get(signature_size, Params2)),
    io:format("✓ Dilithium-2 parameters correct~n"),

    % Test Dilithium-3 parameters
    {ok, Params3} = keylara_dilithium:get_parameter_sizes(dilithium_3),
    ?assertEqual(1952, maps:get(public_key_size, Params3)),
    ?assertEqual(4032, maps:get(private_key_size, Params3)),
    ?assertEqual(3293, maps:get(signature_size, Params3)),
    io:format("✓ Dilithium-3 parameters correct~n"),

    % Test Dilithium-5 parameters
    {ok, Params5} = keylara_dilithium:get_parameter_sizes(dilithium_5),
    ?assertEqual(2592, maps:get(public_key_size, Params5)),
    ?assertEqual(4864, maps:get(private_key_size, Params5)),
    ?assertEqual(4595, maps:get(signature_size, Params5)),
    io:format("✓ Dilithium-5 parameters correct~n"),

    io:format("✓ Parameter sizes test passed~n").

%%%-------------------------------------------------------------------
%%% Test runner
%%%-------------------------------------------------------------------
run_all_tests() ->
    io:format("~n=== Running Dilithium Complete Test Suite ===~n"),
    eunit:test(?MODULE, [verbose]).

