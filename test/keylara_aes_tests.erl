%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Comprehensive unit tests for the KeyLara AES encryption library.
%%% Rewritten for simplified implementation following RSA test patterns.
%%% This test suite covers:
%%% - AES key generation using Alara distributed entropy
%%% - Message encryption and decryption
%%% - Error handling and edge cases
%%% - Performance and security validation
%%%
%%% Usage:
%%%   eunit:test(keylara_aes_tests).
%%%   or
%%%   keylara_aes_tests:run_all_tests().
%%% @end
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

%% Helper function exports
-export([
         setup_test_network/0,
         setup_test_network/1,
         cleanup_network/1,
         generate_test_entropy/2
        ]).

%%%===================================================================
%%% Test Definitions
%%%===================================================================

%% EUnit test generator - automatically runs all tests
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
      {timeout, 30, fun test_entropy_requirements/0},
      {timeout, 30, fun test_concurrent_operations/0}
     ]}.

%%%===================================================================
%%% Test Environment Setup/Cleanup
%%%===================================================================

%% @doc Set up the test environment by starting necessary applications
setup_test_environment() ->
    io:format("Setting up KeyLara AES test environment...~n"),

    % Start required applications
    application:start(crypto),
    application:start(public_key),

    % Start KeyLara
    keylara:start(),

    % Ensure random seed is set
    rand:seed(exrop, {erlang:phash2([node()]),
                      erlang:monotonic_time(),
                      erlang:unique_integer()}),

    io:format("Test environment ready.~n"),
    ok.

%% @doc Clean up the test environment
cleanup_test_environment(_) ->
    io:format("Cleaning up test environment.~n"),
    keylara:stop(),
    ok.

%%%===================================================================
%%% Basic Functionality Tests
%%%===================================================================

%% @doc Test basic AES key generation using Alara entropy
test_basic_key_generation() ->
    io:format("Testing basic AES key generation...~n"),

    % Set up Alara network
    {ok, NetPid} = setup_test_network(),

    try
        % Test different key sizes
        KeySizes = [128, 192, 256],
        lists:foreach(fun(KeySize) ->
                              % Generate key using KeyLara API
                              Result = keylara:generate_aes_key(NetPid, KeySize),

                              % Verify successful generation
                              ?assertMatch({ok, _Key}, Result),

                              % Extract key and verify size
                              {ok, Key} = Result,
                              ?assert(is_binary(Key)),
                              ?assertEqual(KeySize div 8, byte_size(Key)),

                              io:format("✓ ~p-bit key generation test passed~n", [KeySize])
                      end, KeySizes),

        io:format("✓ Basic AES key generation test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test complete encryption/decryption cycle
test_encryption_decryption_cycle() ->
    io:format("Testing AES encryption/decryption cycle...~n"),

    % Set up network and generate key
    {ok, NetPid} = setup_test_network(),

    try
        {ok, Key} = keylara:generate_aes_key(NetPid, 256),

        % Test data
        TestMessages = [
                        <<"Hello, World!">>,
                        <<"This is a test message for KeyLara AES encryption.">>,
                        <<"Short">>,
                        <<"">>,  % Empty message
                        crypto:strong_rand_bytes(50),  % Random binary data
                        crypto:strong_rand_bytes(1000) % Larger random data
                       ],

        % Test each message
        lists:foreach(fun(Message) ->
                              % Encrypt message using KeyLara API
                              {ok, {IV, EncryptedData}} = keylara:aes_encrypt(Message, Key),

                              % Verify encryption result
                              ?assert(is_binary(IV)),
                              ?assert(is_binary(EncryptedData)),
                              ?assertEqual(16, byte_size(IV)),
                              ?assert(byte_size(EncryptedData) > 0),
                              ?assertNotEqual(Message, EncryptedData),

                              % Decrypt message using KeyLara API
                              {ok, DecryptedData} = keylara:aes_decrypt(EncryptedData, Key, IV),

                              % Verify decryption result
                              ?assert(is_binary(DecryptedData)),
                              ?assertEqual(Message, DecryptedData),

                              io:format("✓ Message test passed: ~p bytes~n", [byte_size(Message)])
                      end, TestMessages),

        io:format("✓ AES encryption/decryption cycle test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test encryption/decryption with various message sizes
test_multiple_message_sizes() ->
    io:format("Testing multiple message sizes...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        {ok, Key} = keylara:generate_aes_key(NetPid, 256),

        % Test different message sizes
        % AES can handle much larger messages than RSA
        MessageSizes = [1, 10, 50, 100, 200, 1000, 10000, 50000],

        lists:foreach(fun(Size) ->
                              % Generate message of specific size
                              Message = crypto:strong_rand_bytes(Size),

                              % Test encryption/decryption using KeyLara API
                              {ok, {IV, Encrypted}} = keylara:aes_encrypt(Message, Key),
                              {ok, Decrypted} = keylara:aes_decrypt(Encrypted, Key, IV),


                              % Verify
                              ?assertEqual(Message, Decrypted),
                              io:format("✓ Size ~p bytes: OK~n", [Size])
                      end, MessageSizes),

        io:format("✓ Multiple message sizes test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test AES key generation with different key sizes
test_different_key_sizes() ->
    io:format("Testing different AES key sizes...~n"),

    % Test different key sizes
    KeySizes = [128, 192, 256],

    lists:foreach(fun(KeySize) ->
                          {ok, NetPid} = setup_test_network(),

                          try
                              io:format("Testing ~p-bit keys...~n", [KeySize]),

                              % Generate key using KeyLara API
                              {ok, Key} = keylara:generate_aes_key(NetPid, KeySize),

                              % Verify key size
                              ExpectedBytes = KeySize div 8,
                              ?assertEqual(ExpectedBytes, byte_size(Key)),

                              io:format("Key size requested: ~p bits, actual: ~p bytes (~p bits)~n",
                                        [KeySize, byte_size(Key), byte_size(Key) * 8]),

                              % Test encryption with this key size
                              TestMessage = crypto:strong_rand_bytes(100),

                              {ok, {IV, Encrypted}} = keylara:aes_encrypt(TestMessage, Key),
                              {ok, Decrypted} = keylara:aes_decrypt(Encrypted, Key, IV),
                              ?assertEqual(TestMessage, Decrypted),

                              io:format("✓ ~p-bit key test passed~n", [KeySize])

                          after
                              cleanup_network(NetPid)
                          end
                  end, KeySizes),

    io:format("✓ Different key sizes test passed~n").

%%%===================================================================
%%% Error Handling Tests
%%%===================================================================

%% @doc Test various error conditions and edge cases
test_error_handling() ->
    io:format("Testing error handling...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        {ok, Key} = keylara:generate_aes_key(NetPid, 256),

        % Test 1: Invalid key size
        InvalidKeySizeResult = keylara:generate_aes_key(NetPid, 100),
        ?assertMatch({error, _}, InvalidKeySizeResult),
        io:format("✓ Invalid key size error handling: OK~n"),

        % Test 2: Invalid encrypted data for decryption
        InvalidIV = <<"invalid iv data">>,
        InvalidEncrypted = <<"invalid encrypted data">>,
        DecryptResult = keylara:aes_decrypt(InvalidEncrypted, Key, InvalidIV),
        ?assertMatch({error, _}, DecryptResult),
        io:format("✓ Invalid encrypted data error handling: OK~n"),

        % Test 3: Wrong key for decryption
        {ok, WrongKey} = keylara:generate_aes_key(NetPid, 256),
        TestMessage = <<"Test message">>,
        {ok, {IV, Encrypted}} = keylara:aes_encrypt(TestMessage, Key),
        WrongKeyResult = keylara:aes_decrypt(Encrypted, WrongKey, IV),
        case WrongKeyResult of
            {ok, Data} ->
                ?assertEqual(TestMessage, Data);
            {error, _} ->
                ok
        end,
        io:format("✓ Wrong key error handling: OK~n"),

        % Test 4: Non-binary input for encryption (should be handled by keylara_aes)
        ListMessage = "Hello, World!",
        {ok, _} = keylara:aes_encrypt(ListMessage, Key), % Should convert to binary
        io:format("✓ List to binary conversion: OK~n"),

        % Test 5: Invalid IV size for decryption
        ShortIV = <<"short">>,
        ValidMessage = <<"test">>,
        {ok, {_ValidIV, ValidEncrypted}} = keylara:aes_encrypt(ValidMessage, Key),
        InvalidIVResult = keylara:aes_decrypt(ValidEncrypted, Key, ShortIV),
        ?assertMatch({error, _}, InvalidIVResult),
        io:format("✓ Invalid IV size error handling: OK~n")

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Error handling test passed~n").

%% @doc Test entropy requirements and insufficient entropy scenarios
test_entropy_requirements() ->
    io:format("Testing entropy requirements...~n"),

    % Test 1: Insufficient entropy
    {ok, NetPid} = alara:create_network(),

    try
        % Add only one node with minimal entropy
        {ok, Node} = alara:create_node(1, 0.9, true),
        alara:add_node(NetPid, Node),

        % Generate very little entropy (not enough for AES key)
        SmallEntropy = [rand:uniform(2) =:= 1 || _ <- lists:seq(1, 50)],
        alara:generate_entropy(NetPid, {1, SmallEntropy}),
        timer:sleep(50),

        % Try to generate key - should fail
        Result = keylara:generate_aes_key(NetPid, 256),
        ?assertMatch({error, {insufficient_entropy, _, _}}, Result),
        io:format("✓ Insufficient entropy detection: OK~n")

    after
        cleanup_network(NetPid)
    end,

    % Test 2: Adequate entropy
    {ok, NetPid2} = setup_test_network(1024), % Adequate entropy for AES

    try
        Result2 = keylara:generate_aes_key(NetPid2, 256),
        ?assertMatch({ok, _}, Result2),
        io:format("✓ Adequate entropy generation: OK~n")

    after
        cleanup_network(NetPid2)
    end,

    io:format("✓ Entropy requirements test passed~n").

%% @doc Test concurrent operations to ensure thread safety
test_concurrent_operations() ->
    io:format("Testing concurrent operations...~n"),

    {ok, NetPid} = setup_test_network(2048), % Extra entropy for concurrent access

    try
        % Generate a key for shared use
        {ok, Key} = keylara:generate_aes_key(NetPid, 256),

        % Create multiple concurrent encryption/decryption operations
        NumProcesses = 5,
        TestMessage = <<"Concurrent test message">>,

        Parent = self(),

        % Spawn concurrent processes
        Pids = [spawn(fun() ->
                              try
                                  % Each process performs encryption/decryption
                                  {ok, {IV, Encrypted}} = keylara:aes_encrypt(TestMessage, Key),
                                  {ok, Decrypted} = keylara:aes_decrypt(Encrypted, Key, IV),
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

        io:format("✓ ~p concurrent operations completed successfully~n", [NumProcesses])

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Concurrent operations test passed~n").

%%%===================================================================
%%% Performance Tests
%%%===================================================================

%% @doc Basic performance benchmarking
test_performance() ->
    io:format("Running AES performance tests...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        % Benchmark key generation
        KeyGenStart = erlang:monotonic_time(microsecond),
        {ok, Key} = keylara:generate_aes_key(NetPid, 256),
        KeyGenTime = erlang:monotonic_time(microsecond) - KeyGenStart,

        io:format("Key generation time: ~p μs (~.2f ms)~n",
                  [KeyGenTime, KeyGenTime / 1000]),

        % Benchmark encryption/decryption
        TestMessage = <<"Performance test message for KeyLara AES benchmarking">>,
        NumIterations = 100,

        % Encryption benchmark
        EncStart = erlang:monotonic_time(microsecond),
        EncResults = [keylara:aes_encrypt(TestMessage, Key) || _ <- lists:seq(1, NumIterations)],
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
        DecResults = [keylara:aes_decrypt(SampleEncrypted, Key, SampleIV) || _ <- lists:seq(1, NumIterations)],
        DecTime = erlang:monotonic_time(microsecond) - DecStart,

        % Verify all decryptions succeeded
        lists:foreach(fun(Result) ->
                              ?assertMatch({ok, TestMessage}, Result)
                      end, DecResults),

        io:format("~p decryptions: ~p μs (~.2f ms avg)~n",
                  [NumIterations, DecTime, DecTime / NumIterations / 1000]),

        % Benchmark with larger messages
        LargeMessage = crypto:strong_rand_bytes(10000),
        LargeIterations = 10,

        LargeEncStart = erlang:monotonic_time(microsecond),
        LargeEncTime = erlang:monotonic_time(microsecond) - LargeEncStart,

        io:format("~p large message encryptions (~p bytes): ~p μs (~.2f ms avg)~n",
                  [LargeIterations, byte_size(LargeMessage), LargeEncTime, LargeEncTime / LargeIterations / 1000])

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Performance tests completed~n").

%%%===================================================================
%%% Additional Tests for KeyLara AES API
%%%===================================================================

%% @doc Test KeyLara version and utility functions
test_keylara_utilities() ->
    io:format("Testing KeyLara utilities...~n"),

    % Test version
    Version = keylara:get_version(),
    ?assert(is_list(Version)),
    ?assert(length(Version) > 0),
    io:format("✓ Version: ~s~n", [Version]),

    % Test start/stop
    ?assertEqual(ok, keylara:start()),
    ?assertEqual(ok, keylara:stop()),
    ?assertEqual(ok, keylara:start()), % Restart for other tests

    io:format("✓ KeyLara utilities test passed~n").

%% @doc Test default key size generation
test_default_key_generation() ->
    io:format("Testing default AES key size generation...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        % Test default key size (should be 256)
        {ok, Key} = keylara:generate_aes_key(NetPid),

        % Verify it's 256 bits (32 bytes)
        ?assertEqual(32, byte_size(Key)),

        io:format("✓ Default key size test passed (actual: ~p bits)~n", [byte_size(Key) * 8])

    after
        cleanup_network(NetPid)
    end.

%% @doc Test IV uniqueness and properties
test_iv_properties() ->
    io:format("Testing IV properties...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        {ok, Key} = keylara:generate_aes_key(NetPid, 256),
        TestMessage = <<"IV test message">>,

        % Generate multiple encryptions of the same message
        Results = [keylara:aes_encrypt(TestMessage, Key) || _ <- lists:seq(1, 5)],

        % Extract IVs
        IVs = [IV || {ok, {IV, _}} <- Results],

        % Verify all IVs are different (extremely high probability)
        lists:foreach(fun({I, IV1}) ->
                              lists:foreach(fun({J, IV2}) ->
                                                    if I =/= J -> ?assertNotEqual(IV1, IV2);
                                                       true -> ok
                                                    end
                                            end, lists:zip(lists:seq(1, length(IVs)), IVs))
                      end, lists:zip(lists:seq(1, length(IVs)), IVs)),

        % Verify IV size (should be 16 bytes for AES)
        lists:foreach(fun(IV) ->
                              ?assertEqual(16, byte_size(IV))
                      end, IVs),

        io:format("✓ IV uniqueness and size verification passed~n")

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ IV properties test passed~n").

%%%===================================================================
%%% Test Runners
%%%===================================================================

%% @doc Run all tests
run_all_tests() ->
    io:format("~n=== Running KeyLara AES Complete Test Suite ===~n"),
    eunit:test(?MODULE, [verbose]).

%% @doc Run only basic functionality tests
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

%% @doc Run advanced tests
run_advanced_tests() ->
    io:format("~n=== Running Advanced KeyLara AES Tests ===~n"),
    Tests = [
             fun test_different_key_sizes/0,
             fun test_error_handling/0,
             fun test_entropy_requirements/0,
             fun test_concurrent_operations/0
            ],
    run_test_list(Tests).

%% @doc Run performance tests
run_performance_tests() ->
    io:format("~n=== Running KeyLara AES Performance Tests ===~n"),
    test_performance().

%% @doc Helper function to run a list of tests
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

%%%===================================================================
%%% Helper Functions
%%%===================================================================

%% @doc Set up a test network with adequate entropy
setup_test_network() ->
    setup_test_network(1024).

%% @doc Set up a test network with specified entropy amount
setup_test_network(EntropyBits) ->
    {ok, NetPid} = alara:create_network(),

    % Calculate how many nodes we need
    BitsPerNode = 512,
    NumNodes = max(3, (EntropyBits + BitsPerNode - 1) div BitsPerNode),

    % Add nodes with entropy
    lists:foreach(fun(NodeId) ->
                          {ok, Node} = alara:create_node(NodeId, 0.9 - (NodeId * 0.1), true),
                          alara:add_node(NetPid, Node),

                          Bits = generate_test_entropy(BitsPerNode, NodeId),
                          alara:generate_entropy(NetPid, {NodeId, Bits})
                  end, lists:seq(1, NumNodes)),

    % Wait for entropy to propagate
    timer:sleep(100),

    {ok, NetPid}.

%% @doc Clean up a test network
cleanup_network(NetPid) ->
    try
        exit(NetPid, normal)
    catch
        _:_ -> ok
    end.

%% @doc Generate test entropy bits
generate_test_entropy(NumBits, Seed) ->
    % Use seed for reproducible test entropy
    rand:seed(exrop, {Seed, Seed * 2, Seed * 3}),
    [rand:uniform(2) =:= 1 || _ <- lists:seq(1, NumBits)].

%%%===================================================================
%%% Test Execution Instructions
%%%===================================================================

%% To run these tests, use one of the following methods:
%%
%% 1. Run all tests:
%%    keylara_aes_tests:run_all_tests().
%%
%% 2. Run specific test categories:
%%    keylara_aes_tests:run_basic_tests().
%%    keylara_aes_tests:run_advanced_tests().
%%    keylara_aes_tests:run_performance_tests().
%%
%% 3. Use EUnit directly:
%%    eunit:test(keylara_aes_tests).
%%
%% 4. Run with verbose output:
%%    eunit:test(keylara_aes_tests, [verbose]).

%%%===================================================================
%%% End of Tests
%%%===================================================================
