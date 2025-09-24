%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Unit tests for the KeyLara Dilithium post-quantum signature module.
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
         fun test_keypair_generation/0,
         fun test_invalid_parameters/0,
         fun test_format_validations/0,
         fun test_signature_format_errors/0
     ]}.

%%%--------------------
%%% Setup/cleanup
%%%--------------------
setup_test_environment() ->
    application:start(crypto),
    %% Keylara (and optionally simulated nodes) should be started here if needed.
    ok.

cleanup_test_environment(_Ctx) ->
    application:stop(crypto),
    ok.

%%%--------------------------
%%% Test: Keypair generation
%%%--------------------------
test_keypair_generation() ->
    %% Simulate remote entropy gathering
    DummyNetPid = self(),  %% In production, should be a true ND node pid
    {error, _} = keylara_dilithium:generate_keypair(DummyNetPid, bad_level),
    {error, _} = keylara_dilithium:generate_keypair(undefined, dilithium_2),
    %% Actual keypair test would require working entropy and nodes.
    ok.

%%%--------------------------------------
%%% Test: Parameter/Format Validations
%%%--------------------------------------
test_format_validations() ->
    %% Verify known good sizes pass
    ?assertEqual(ok, keylara_dilithium:validate_public_key(crypto:strong_rand_bytes(1312), dilithium_2)),
    ?assertEqual(ok, keylara_dilithium:validate_private_key(crypto:strong_rand_bytes(2528), dilithium_2)),
    ?assertEqual(ok, keylara_dilithium:validate_signature(crypto:strong_rand_bytes(2420), dilithium_2)),
    %% Wrong sizes should be errors
    ?assertMatch({error, _}, keylara_dilithium:validate_public_key(crypto:strong_rand_bytes(100), dilithium_2)),
    ?assertMatch({error, _}, keylara_dilithium:validate_private_key(crypto:strong_rand_bytes(99), dilithium_2)),
    ?assertMatch({error, _}, keylara_dilithium:validate_signature(crypto:strong_rand_bytes(1), dilithium_2)),
    ok.

%%%--------------------------------------
%%% Test: Invalid parameter error handling
%%%--------------------------------------
test_invalid_parameters() ->
    ?assertMatch({error, {invalid_parameter_set, _}}, keylara_dilithium:get_parameter_sizes(badparam)),
    ?assertMatch({error, {invalid_parameter_set, _}}, keylara_dilithium:validate_public_key(<<1,2,3>>, badparam)),
    ok.

%%%--------------------------------------
%%% Test: Signature format validation
%%%--------------------------------------
test_signature_format_errors() ->
    %% Not a binary
    ?assertMatch({error, invalid_signature_format}, keylara_dilithium:validate_signature(notabinary, dilithium_2)),
    ?assertMatch({error, invalid_public_key_format}, keylara_dilithium:validate_public_key([1,2,3], dilithium_2)),
    ok.

%%%-------------------------------------------------------------------
%%% Test runner
%%%-------------------------------------------------------------------
run_all_tests() ->
    eunit:test(?MODULE, [verbose]).

