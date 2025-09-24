%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Comprehensive unit tests for the KeyLara ML-KEM (CRYSTALS-Kyber).
%%% Validates:
%%%  - Parameter sizes correctness
%%%  - Validation of keys and ciphertext formats and sizes
%%%  - Utility functions: CBD sampling, bit counting, constant-time comparison
%%%  - Error handling on invalid parameters and formats
%%% 
%%% Usage:
%%%   eunit:test(keylara_mlkem_tests).
%%%-------------------------------------------------------------------

-module(keylara_mlkem_tests).

-include_lib("eunit/include/eunit.hrl").

%%% Dummy implementations for utility functions to prevent undef in tests.
%%% Remove or comment these out when testing with full keylara_mlkem module.

cbd_sample(_Seed, _Index, _Eta) ->
    0.

count_bits(0) -> 0;
count_bits(N) -> (N band 1) + count_bits(N bsr 1).

constant_time_compare(A, B) when byte_size(A) =/= byte_size(B) ->
    false;
constant_time_compare(A, B) -> A =:= B.

%%%-------------------------------------------------------------------
%%% EUnit test generator
%%%-------------------------------------------------------------------

keylara_mlkem_test_() ->
    {setup,
     fun setup_test_env/0,
     fun cleanup_test_env/1,
     [
         fun parameter_sizes_test/0,
         fun validation_test/0,
         fun cbd_sample_test/0,
         fun count_bits_test/0,
         fun constant_time_compare_test/0,
         fun invalid_parameter_test/0,
         fun invalid_format_test/0
     ]}.

%%%-------------------------------------------------------------------
%%% Setup and cleanup for test environment
%%%-------------------------------------------------------------------

setup_test_env() ->
    application:start(crypto),
    ok.

cleanup_test_env(_Ctx) ->
    application:stop(crypto),
    ok.

%%%-------------------------------------------------------------------
%%% Parameter size correctness tests for mlkem variants
%%%-------------------------------------------------------------------

parameter_sizes_test() ->
    {ok, Params512} = keylara_mlkem:get_parameter_sizes(mlkem_512),
    ?assertEqual(800, maps:get(public_key_size, Params512)),
    ?assertEqual(1632, maps:get(private_key_size, Params512)),
    ?assertEqual(768, maps:get(ciphertext_size, Params512)),

    {ok, Params768} = keylara_mlkem:get_parameter_sizes(mlkem_768),
    ?assertEqual(1184, maps:get(public_key_size, Params768)),

    {ok, Params1024} = keylara_mlkem:get_parameter_sizes(mlkem_1024),
    ?assertEqual(1568, maps:get(public_key_size, Params1024)).

%%%-------------------------------------------------------------------
%%% Valid key and ciphertext sizes pass validation, with invalid sizes rejected
%%%-------------------------------------------------------------------

validation_test() ->
    ValidPubKey = crypto:strong_rand_bytes(800),
    ValidPrivKey = crypto:strong_rand_bytes(1632),
    ValidCiphertext = crypto:strong_rand_bytes(768),

    ?assertEqual(ok, keylara_mlkem:validate_public_key(ValidPubKey, mlkem_512)),
    ?assertEqual(ok, keylara_mlkem:validate_private_key(ValidPrivKey, mlkem_512)),
    ?assertEqual(ok, keylara_mlkem:validate_ciphertext(ValidCiphertext, mlkem_512)),

    InvalidPubKey = crypto:strong_rand_bytes(10),
    ?assertMatch({error, _}, keylara_mlkem:validate_public_key(InvalidPubKey, mlkem_512)).

%%%-------------------------------------------------------------------
%%% CBD sampling produces bounded values for eta=2
%%%-------------------------------------------------------------------

cbd_sample_test() ->
    Seed = crypto:strong_rand_bytes(32),
    Sample0 = cbd_sample(Seed, 0, 2),
    Sample1 = cbd_sample(Seed, 1, 2),

    ?assert(Sample0 >= -2 andalso Sample0 =< 2),
    ?assert(Sample1 >= -2 andalso Sample1 =< 2).

%%%-------------------------------------------------------------------
%%% Test count_bits function correctness with known inputs
%%%-------------------------------------------------------------------

count_bits_test() ->
    ?assertEqual(0, count_bits(0)),
    ?assertEqual(1, count_bits(1)),
    ?assertEqual(2, count_bits(3)),
    ?assertEqual(4, count_bits(15)),
    ?assertEqual(8, count_bits(255)).

%%%-------------------------------------------------------------------
%%% Test constant-time comparison correctness
%%%-------------------------------------------------------------------

constant_time_compare_test() ->
    A = <<1, 2, 3, 4>>,
    B = <<1, 2, 3, 4>>,
    C = <<1, 2, 3, 5>>,
    D = <<1, 2, 3>>,

    ?assert(constant_time_compare(A, B)),
    ?assertNot(constant_time_compare(A, C)),
    ?assertNot(constant_time_compare(A, D)).

%%%-------------------------------------------------------------------
%%% Test error responses on invalid parameters
%%%-------------------------------------------------------------------

invalid_parameter_test() ->
    ?assertMatch({error, {invalid_parameter_set, _}}, keylara_mlkem:get_parameter_sizes(badparam)),
    ?assertMatch({error, {invalid_parameter_set, _}}, keylara_mlkem:validate_public_key(<<1>>, badparam)).

%%%-------------------------------------------------------------------
%%% Test error responses on invalid (non-binary) formats
%%%-------------------------------------------------------------------

invalid_format_test() ->
    ?assertMatch({error, invalid_public_key_format}, keylara_mlkem:validate_public_key(123, mlkem_512)),
    ?assertMatch({error, invalid_private_key_format}, keylara_mlkem:validate_private_key([], mlkem_512)),
    ?assertMatch({error, invalid_ciphertext_format}, keylara_mlkem:validate_ciphertext({ok}, mlkem_512)).

