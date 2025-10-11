%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Comprehensive unit tests for the KeyLara AES encryption library.
%%% Updated for centralized entropy management.
%%%-------------------------------------------------------------------

-module(keylara_aes_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%% Test runner exports
-export([
    run_all_tests/0,
    run_basic_tests/0,
    run_advanced_tests/0,
    run_performance_tests/0
]).

%%%===================================================================
%%% Test Definitions
%%%===================================================================

keylara_aes_test_() ->
    {setup,
     fun setup_test_environment/0,
     fun cleanup_test_environment/1,
     [
         {timeout, 30, fun test_basic_key_generation/0},
         {timeout, 30, fun test_encryption_decryption_cycle/0},
         {timeout, 30, fun test_multiple_message_sizes/0},
         {timeout, 30, fun test_different_key_sizes/0},
         {timeout, 30, fun test_error_handling/0},
         {timeout, 30, fun test_concurrent_operations/0},
         {timeout, 30, fun test_keylara_utilities/0},
         {timeout, 30, fun test_default_key_generation/0},
         {timeout, 30, fun test_iv_properties/0}
     ]}.

%%%===================================================================
%%% Test Environment Setup/Cleanup
%%%===================================================================

setup_test_environment() ->
    io:format("Setting up KeyLara AES test environment...~n"),
    application:start(crypto),
    application:start(public_key),
    keylara:start(),
    rand:seed(exrop, {erlang:phash2([node()]),
                      erlang:monotonic_time(),
                      erlang:unique_integer()}),
    io:format("Test environment ready.~n"),
    ok.

cleanup_test_environment(_) ->
    io:format("Cleaning up test environment.~n"),
    keylara:stop(),
    application:stop(public_key),
    application:stop(crypto),
    ok.

%%%===================================================================
%%% Basic Functionality Tests
%%%===================================================================

test_basic_key_generation() ->
    io:format("Testing basic AES key generation...~n"),

    % Test different key sizes
    KeySizes = [128, 192, 256],
    lists:foreach(fun(KeySize) ->
        % Generate key using KeyLara API
        Result = keylara_aes:generate_key(KeySize),

        % Verify successful generation
        ?assertMatch({ok, _Key}, Result),

        % Extract key and verify size
        {ok, Key} = Result,
        ?assert(is_binary(Key)),
        ?assertEqual(KeySize div 8, byte_size(Key)),

        io:format("✓ ~p-bit key generation test passed~n", [KeySize])
    end, KeySizes),

    io:format("✓ Basic AES key generation test passed~n").

test_encryption_decryption_cycle() ->
    io:format("Testing AES encryption/decryption cycle...~n"),

    {ok, Key} = keylara_aes:generate_key(256),

    % Test data
    TestMessages = [
        <<"Hello, World!">>,
        <<"This is a test message for KeyLara AES encryption.">>,
        <<"Short">>,
        <<"">>,
        crypto:strong_rand_bytes(50),
        crypto:strong_rand_bytes(1000)
    ],

    % Test each message
    lists:foreach(fun(Message) ->
        % Encrypt message
        {ok, {IV, EncryptedData}} = keylara_aes:encrypt(Message, Key),

        % Verify encryption result
        ?assert(is_binary(IV)),
        ?assert(is_binary(EncryptedData)),
        ?assertEqual(16, byte_size(IV)),
        ?assert(byte_size(EncryptedData) > 0),
        ?assertNotEqual(Message, EncryptedData),

        % Decrypt message
        {ok, DecryptedData} = keylara_aes:decrypt(EncryptedData, Key, IV),

        % Verify decryption result
        ?assert(is_binary(DecryptedData)),
        ?assertEqual(Message, DecryptedData),

        io:format("✓ Message test passed: ~p bytes~n", [byte_size(Message)])
    end, TestMessages),

    io:format("✓ AES encryption/decryption cycle test passed~n").

test_multiple_message_sizes() ->
    io:format("Testing multiple message sizes...~n"),

    {ok, Key} = keylara_aes:generate_key(256),

    % Test different message sizes
    MessageSizes = [1, 10, 50, 100, 200, 1000, 10000, 50000],

    lists:foreach(fun(Size) ->
        % Generate message of specific size
        Message = crypto:strong_rand_bytes(Size),

        % Test encryption/decryption
        {ok, {IV, Encrypted}} = keylara_aes:encrypt(Message, Key),
        {ok, Decrypted} = keylara_aes:decrypt(Encrypted, Key, IV),

        % Verify
        ?assertEqual(Message, Decrypted),
        io:format("✓ Size ~p bytes: OK~n", [Size])
    end, MessageSizes),

    io:format("✓ Multiple message sizes test passed~n").

test_different_key_sizes() ->
    io:format("Testing different AES key sizes...~n"),

    % Test different key sizes
    KeySizes = [128, 192, 256],

    lists:foreach(fun(KeySize) ->
        io:format("Testing ~p-bit keys...~n", [KeySize]),

        % Generate key
        {ok, Key} = keylara_aes:generate_key(KeySize),

        % Verify key size
        ExpectedBytes = KeySize div 8,
        ?assertEqual(ExpectedBytes, byte_size(Key)),

        io:format("Key size requested: ~p bits, actual: ~p bytes (~p bits)~n",
                 [KeySize, byte_size(Key), byte_size(Key) * 8]),

        % Test encryption with this key size
        TestMessage = crypto:strong_rand_bytes(100),

        {ok, {IV, Encrypted}} = keylara_aes:encrypt(TestMessage, Key),
        {ok, Decrypted} = keylara_aes:decrypt(Encrypted, Key, IV),
        ?assertEqual(TestMessage, Decrypted),

        io:format("✓ ~p-bit key test passed~n", [KeySize])
    end, KeySizes),

    io:format("✓ Different key sizes test passed~n").

%%%===================================================================
%%% Error Handling Tests
%%%===================================================================

test_error_handling() ->
    io:format("Testing error handling...~n"),

    {ok, Key} = keylara_aes:generate_key(256),

    % Test 1: Invalid key size
    InvalidKeySizeResult = keylara_aes:generate_key(100),
    ?assertMatch({error, _}, InvalidKeySizeResult),
    io:format("✓ Invalid key size error handling: OK~n"),

    % Test 2: Invalid encrypted data for decryption
    InvalidIV = <<"invalid iv data">>,
    InvalidEncrypted = <<"invalid encrypted data">>,
    DecryptResult = keylara_aes:decrypt(InvalidEncrypted, Key, InvalidIV),
    ?assertMatch({error, _}, DecryptResult),
    io:format("✓ Invalid encrypted data error handling: OK~n"),

    % Test 3: Wrong key for decryption
    {ok, WrongKey} = keylara_aes:generate_key(256),
    TestMessage = <<"Test message">>,
    {ok, {IV, Encrypted}} = keylara_aes:encrypt(TestMessage, Key),
    WrongKeyResult = keylara_aes:decrypt(Encrypted, WrongKey, IV),
    case WrongKeyResult of
        {ok, Data} -> ?assertNotEqual(TestMessage, Data);
        {error, _} -> ok
    end,
    io:format("✓ Wrong key error handling: OK~n"),

    % Test 4: Non-binary input for encryption
    ListMessage = "Hello, World!",
    {ok, _} = keylara_aes:encrypt(ListMessage, Key),
    io:format("✓ List to binary conversion: OK~n"),

    % Test 5: Invalid IV size for decryption
    ShortIV = <<"short">>,
    ValidMessage = <<"test">>,
    {ok, {_ValidIV, ValidEncrypted}} = keylara_aes:encrypt(ValidMessage, Key),
    InvalidIVResult = keylara_aes:decrypt(ValidEncrypted, Key, ShortIV),
    ?assertMatch({error, _}, InvalidIVResult),
    io:format("✓ Invalid IV size error handling: OK~n"),

    io:format("✓ Error handling test passed~n").

test_concurrent_operations() ->
    io:format("Testing concurrent operations...~n"),

    % Generate a key for shared use
    {ok, Key} = keylara_aes:generate_key(256),

    % Create multiple concurrent encryption/decryption operations
    NumProcesses = 5,
    TestMessage = <<"Concurrent test message">>,

    Parent = self(),

    % Spawn concurrent processes
    Pids = [spawn(fun() ->
        try
            % Each process performs encryption/decryption
            {ok, {IV, Encrypted}} = keylara_aes:encrypt(TestMessage, Key),
            {ok, Decrypted} = keylara_aes:decrypt(Encrypted, Key, IV),
            ?assertEqual(TestMessage, Decrypted),
            Parent ! {self(), success}
        catch
            Error:Reason ->
                Parent ! {self(), {error, Error, Reason}}
        end
    end) || _ <- lists:seq(1, NumProcesses)],

    % Wait for all processes to complete
    Results = [receive
        {Pid, Result} -> Result
    after 10000 ->
        timeout
    end || Pid <- Pids],

    % Verify all operations succeeded
    lists:foreach(fun(Result) ->
        ?assertEqual(success, Result)
    end, Results),

    io:format("✓ ~p concurrent operations completed successfully~n", [NumProcesses]),
    io:format("✓ Concurrent operations test passed~n").

%%%===================================================================
%%% Performance Tests
%%%===================================================================

test_performance() ->
    io:format("Running AES performance tests...~n"),

    % Benchmark key generation
    KeyGenStart = erlang:monotonic_time(microsecond),
    {ok, Key} = keylara_aes:generate_key(256),
    KeyGenTime = erlang:monotonic_time(microsecond) - KeyGenStart,

    io:format("Key generation time: ~p μs (~.2f ms)~n",
             [KeyGenTime, KeyGenTime / 1000]),

    % Benchmark encryption/decryption
    TestMessage = <<"Performance test message for KeyLara AES benchmarking">>,
    NumIterations = 100,

    % Encryption benchmark
    EncStart = erlang:monotonic_time(microsecond),
    EncResults = [keylara_aes:encrypt(TestMessage, Key) || _ <- lists:seq(1, NumIterations)],
    EncTime = erlang:monotonic_time(microsecond) - EncStart,

    % Verify all encryptions succeeded
    lists:foreach(fun(Result) ->
        ?assertMatch({ok, {_, _}}, Result)
    end, EncResults),

    io:format("~p encryptions: ~p μs (~.2f ms avg)~n",
             [NumIterations, EncTime, EncTime / NumIterations / 1000]),

    % Decryption benchmark
    [{ok, {SampleIV, SampleEncrypted}} | _] = EncResults,
    DecStart = erlang:monotonic_time(microsecond),
    DecResults = [keylara_aes:decrypt(SampleEncrypted, Key, SampleIV) || _ <- lists:seq(1, NumIterations)],
    DecTime = erlang:monotonic_time(microsecond) - DecStart,

    % Verify all decryptions succeeded
    lists:foreach(fun(Result) ->
        ?assertMatch({ok, TestMessage}, Result)
    end, DecResults),

    io:format("~p decryptions: ~p μs (~.2f ms avg)~n",
             [NumIterations, DecTime, DecTime / NumIterations / 1000]),

    io:format("✓ Performance tests completed~n").

%%%===================================================================
%%% Additional Tests
%%%===================================================================

test_keylara_utilities() ->
    io:format("Testing KeyLara utilities...~n"),

    % Test version
    Version = keylara:get_version(),
    ?assert(is_list(Version)),
    ?assert(length(Version) > 0),
    io:format("✓ Version: ~s~n", [Version]),

    io:format("✓ KeyLara utilities test passed~n").

test_default_key_generation() ->
    io:format("Testing default AES key size generation...~n"),

    % Test default key size (should be 256)
    {ok, Key} = keylara_aes:generate_key(),

    % Verify it's 256 bits (32 bytes)
    ?assertEqual(32, byte_size(Key)),

    io:format("✓ Default key size test passed (actual: ~p bits)~n", [byte_size(Key) * 8]).

test_iv_properties() ->
    io:format("Testing IV properties...~n"),

    {ok, Key} = keylara_aes:generate_key(256),
    TestMessage = <<"IV test message">>,

    % Generate multiple encryptions of the same message
    Results = [keylara_aes:encrypt(TestMessage, Key) || _ <- lists:seq(1, 5)],

    % Extract IVs
    IVs = [IV || {ok, {IV, _}} <- Results],

    % Verify all IVs are different
    lists:foreach(fun({I, IV1}) ->
        lists:foreach(fun({J, IV2}) ->
            if I =/= J -> ?assertNotEqual(IV1, IV2);
               true -> ok
            end
        end, lists:zip(lists:seq(1, length(IVs)), IVs))
    end, lists:zip(lists:seq(1, length(IVs)), IVs)),

    % Verify IV size
    lists:foreach(fun(IV) ->
        ?assertEqual(16, byte_size(IV))
    end, IVs),

    io:format("✓ IV uniqueness and size verification passed~n"),
    io:format("✓ IV properties test passed~n").

%%%===================================================================
%%% Test Runners
%%%===================================================================

run_all_tests() ->
    io:format("~n=== Running KeyLara AES Complete Test Suite ===~n"),
    eunit:test(?MODULE, [verbose]).

run_basic_tests() ->
    io:format("~n=== Running Basic KeyLara AES Tests ===~n"),
    Tests = [
        fun test_basic_key_generation/0,
        fun test_encryption_decryption_cycle/0,
        fun test_multiple_message_sizes/0,
        fun test_default_key_generation/0,
        fun test_keylara_utilities/0,
        fun test_iv_properties/0
    ],
    run_test_list(Tests).

run_advanced_tests() ->
    io:format("~n=== Running Advanced KeyLara AES Tests ===~n"),
    Tests = [
        fun test_different_key_sizes/0,
        fun test_error_handling/0,
        fun test_concurrent_operations/0
    ],
    run_test_list(Tests).

run_performance_tests() ->
    io:format("~n=== Running KeyLara AES Performance Tests ===~n"),
    test_performance().

run_test_list(Tests) ->
    setup_test_environment(),
    try
        lists:foreach(fun(TestFun) ->
            try
                TestFun(),
                io:format("✓ Test passed~n")
            catch
                Class:Reason:Stacktrace ->
                    io:format("✗ Test failed: ~p:~p~n", [Class, Reason]),
                    io:format("Stacktrace: ~p~n", [Stacktrace])
            end
        end, Tests)
    after
        cleanup_test_environment(ok)
    end.

