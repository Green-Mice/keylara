%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Unit tests for the KeyLara SLH-DSA post-quantum signature module.
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
         fun test_keypair_generation/0,
         fun test_invalid_parameters/0,
         fun test_format_validations/0,
         fun test_signature_format_errors/0
     ]}.

%%%--------------------
%%% Setup/cleanup
%%%--------------------
setup_test_environment() ->
    %% Start crypto application for cryptographic functions
    application:start(crypto),
    ok.

cleanup_test_environment(_Ctx) ->
    %% Stop the crypto application cleanly
    application:stop(crypto),
    ok.

%%%--------------------------
%%% Test: Keypair generation
%%%--------------------------
test_keypair_generation() ->
    %% Simulate distributed entropy gathering with dummy pid
    DummyNetPid = self(),  %% In production, this should be a real network daemon pid
    ?assertMatch({error, _}, keylara_slhdsa:generate_keypair(DummyNetPid, bad_level)),
    ?assertMatch({error, _}, keylara_slhdsa:generate_keypair(undefined, ?SLH_DSA_SHA2_128S)),
    %% Note: real keypair generation tests require working entropy and nodes
    ok.

%%%--------------------------------------
%%% Test: Parameter and format validations
%%%--------------------------------------
test_format_validations() ->
    %% Known valid sizes should pass
    ?assertEqual(ok, keylara_slhdsa:validate_public_key(crypto:strong_rand_bytes(32), ?SLH_DSA_SHA2_128S)),
    ?assertEqual(ok, keylara_slhdsa:validate_private_key(crypto:strong_rand_bytes(64), ?SLH_DSA_SHA2_128S)),
    ?assertEqual(ok, keylara_slhdsa:validate_signature(crypto:strong_rand_bytes(7856), ?SLH_DSA_SHA2_128S)),

    %% Invalid sizes should raise errors
    ?assertMatch({error, _}, keylara_slhdsa:validate_public_key(crypto:strong_rand_bytes(10), ?SLH_DSA_SHA2_128S)),
    ?assertMatch({error, _}, keylara_slhdsa:validate_private_key(crypto:strong_rand_bytes(10), ?SLH_DSA_SHA2_128S)),
    ?assertMatch({error, _}, keylara_slhdsa:validate_signature(crypto:strong_rand_bytes(10), ?SLH_DSA_SHA2_128S)),
    ok.

%%%--------------------------------------
%%% Test: Invalid parameter set handling
%%%--------------------------------------
test_invalid_parameters() ->
    ?assertMatch({error, {invalid_parameter_set, _}}, keylara_slhdsa:get_parameter_sizes(badparam)),
    ?assertMatch({error, {invalid_parameter_set, _}}, keylara_slhdsa:validate_public_key(<<1,2,3>>, badparam)),
    ok.

%%%--------------------------------------
%%% Test: Signature and key format errors
%%%--------------------------------------
test_signature_format_errors() ->
    %% Passing non-binary to validate_signature must raise error
    ?assertMatch({error, invalid_signature_format}, keylara_slhdsa:validate_signature(notabinary, ?SLH_DSA_SHA2_128S)),
    %% Non-binaries to public/private key validations raise errors
    ?assertMatch({error, invalid_public_key_format}, keylara_slhdsa:validate_public_key([1,2,3], ?SLH_DSA_SHA2_128S)),
    ?assertMatch({error, invalid_private_key_format}, keylara_slhdsa:validate_private_key(#{map=>not_valid}, ?SLH_DSA_SHA2_128S)),
    ok.

%%%-------------------------------------------------------------------
%%% Test runner for manual execution (optional)
%%%-------------------------------------------------------------------
run_all_tests() ->
    eunit:test(?MODULE, [verbose]).

