%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Comprehensive unit tests for the KeyLara RSA encryption library.
%%% Rewritten for simplified implementation.
%%% This test suite covers:
%%% - RSA keypair generation using Alara distributed entropy
%%% - Message encryption and decryption
%%% - Error handling and edge cases
%%% - Performance and security validation
%%%
%%% Usage:
%%%   eunit:test(keylara_rsa_tests).
%%%   or
%%%   keylara_rsa_tests:run_all_tests().
%%% @end
%%%-------------------------------------------------------------------

-module(keylara_rsa_tests).

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
keylara_rsa_test_() ->
    {setup,
     fun setup_test_environment/0,
     fun cleanup_test_environment/1,
     [
         {timeout, 30, fun test_basic_keypair_generation/0},
         {timeout, 30, fun test_encryption_decryption_cycle/0},
         {timeout, 30, fun test_multiple_message_sizes/0},
         {timeout, 30, fun test_different_key_sizes/0},
         {timeout, 30, fun test_error_handling/0},
         {timeout, 30, fun test_entropy_requirements/0},
         {timeout, 30, fun test_key_consistency/0},
         {timeout, 30, fun test_concurrent_operations/0}
     ]}.

%%%===================================================================
%%% Test Environment Setup/Cleanup
%%%===================================================================

%% @doc Set up the test environment by starting necessary applications
setup_test_environment() ->
    io:format("Setting up KeyLara test environment...~n"),

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
%%% Helper Functions for Key Size Calculation
%%%===================================================================

%% @doc Calculate the bit size of an integer
integer_bit_size(N) when N > 0 ->
    integer_bit_size(N, 0).

integer_bit_size(0, Acc) ->
    Acc;
integer_bit_size(N, Acc) ->
    integer_bit_size(N bsr 1, Acc + 1).

%%%===================================================================
%%% Basic Functionality Tests
%%%===================================================================

%% @doc Test basic RSA keypair generation using Alara entropy
test_basic_keypair_generation() ->
    io:format("Testing basic keypair generation...~n"),

    % Set up Alara network
    {ok, NetPid} = setup_test_network(),

    try
        % Generate RSA keypair using KeyLara API
        Result = keylara_rsa:generate_keypair(NetPid, 1024),

        % Verify successful generation
        ?assertMatch({ok, {_PublicKey, _PrivateKey}}, Result),

        % Extract keys and verify structure
        {ok, {PublicKey, PrivateKey}} = Result,

        % Verify public key structure
        ?assertMatch(#'RSAPublicKey'{modulus = _, publicExponent = _}, PublicKey),
        ?assert(is_integer(PublicKey#'RSAPublicKey'.modulus)),
        ?assert(PublicKey#'RSAPublicKey'.publicExponent > 0),

        % Verify private key structure
        ?assertMatch(#'RSAPrivateKey'{modulus = _, publicExponent = _,
                                      privateExponent = _, prime1 = _,
                                      prime2 = _}, PrivateKey),

        % Verify key consistency (same modulus and public exponent)
        ?assertEqual(PublicKey#'RSAPublicKey'.modulus,
                     PrivateKey#'RSAPrivateKey'.modulus),
        ?assertEqual(PublicKey#'RSAPublicKey'.publicExponent,
                     PrivateKey#'RSAPrivateKey'.publicExponent),

        io:format("✓ Basic keypair generation test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test complete encryption/decryption cycle
test_encryption_decryption_cycle() ->
    io:format("Testing encryption/decryption cycle...~n"),

    % Set up network and generate keys
    {ok, NetPid} = setup_test_network(),

    try
        {ok, {PublicKey, PrivateKey}} = keylara_rsa:generate_keypair(NetPid, 1024),

        % Test data
        TestMessages = [
            <<"Hello, World!">>,
            <<"This is a test message for KeyLara encryption.">>,
            <<"Short">>,
            <<"">>,  % Empty message
            crypto:strong_rand_bytes(50)  % Random binary data
        ],

        % Test each message
        lists:foreach(fun(Message) ->
            % Encrypt message using KeyLara API
            {ok, EncryptedData} = keylara_rsa:encrypt(Message, PublicKey),

            % Verify encryption result
            ?assert(is_binary(EncryptedData)),
            ?assert(byte_size(EncryptedData) > 0),
            ?assertNotEqual(Message, EncryptedData),

            % Decrypt message using KeyLara API
            {ok, DecryptedData} = keylara_rsa:decrypt(EncryptedData, PrivateKey),

            % Verify decryption result
            ?assert(is_binary(DecryptedData)),
            ?assertEqual(Message, DecryptedData),

            io:format("✓ Message test passed: ~p bytes~n", [byte_size(Message)])
        end, TestMessages),

        io:format("✓ Encryption/decryption cycle test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test encryption/decryption with various message sizes
test_multiple_message_sizes() ->
    io:format("Testing multiple message sizes...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        {ok, {PublicKey, PrivateKey}} = keylara_rsa:generate_keypair(NetPid, 2048),

        % Test different message sizes (RSA can encrypt up to key_size/8 - 11 bytes for PKCS#1 v1.5)
        % For 2048-bit key: max ~245 bytes
        MessageSizes = [1, 10, 50, 100, 200, 245],

        lists:foreach(fun(Size) ->
            % Generate message of specific size
            Message = crypto:strong_rand_bytes(Size),

            % Test encryption/decryption using KeyLara API
            {ok, Encrypted} = keylara_rsa:encrypt(Message, PublicKey),
            {ok, Decrypted} = keylara_rsa:decrypt(Encrypted, PrivateKey),

            % Verify
            ?assertEqual(Message, Decrypted),
            io:format("✓ Size ~p bytes: OK~n", [Size])
        end, MessageSizes),

        io:format("✓ Multiple message sizes test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test RSA keypair generation with different key sizes
test_different_key_sizes() ->
    io:format("Testing different RSA key sizes...~n"),

    % Test different key sizes
    KeySizes = [1024, 2048],  % 4096 takes too long for unit tests

    lists:foreach(fun(KeySize) ->
        {ok, NetPid} = setup_test_network(KeySize * 2), % Ensure enough entropy

        try
            io:format("Testing ~p-bit keys...~n", [KeySize]),

            % Generate keypair using KeyLara API
            {ok, {PublicKey, PrivateKey}} = keylara_rsa:generate_keypair(NetPid, KeySize),

            % Verify key size - using proper bit size calculation
            Modulus = PublicKey#'RSAPublicKey'.modulus,
            ModulusBitSize = integer_bit_size(Modulus),

            io:format("Key size requested: ~p bits, actual modulus: ~p bits~n",
                     [KeySize, ModulusBitSize]),

            % RSA modulus should be close to the requested key size
            % Allow some tolerance as the actual size can vary slightly
            ?assert(ModulusBitSize >= KeySize - 8),
            ?assert(ModulusBitSize =< KeySize + 8),

            % Test encryption with this key size
            MaxMessageSize = KeySize div 8 - 11, % PKCS#1 v1.5 padding
            TestMessage = crypto:strong_rand_bytes(min(50, MaxMessageSize)),

            {ok, Encrypted} = keylara_rsa:encrypt(TestMessage, PublicKey),
            {ok, Decrypted} = keylara_rsa:decrypt(Encrypted, PrivateKey),
            ?assertEqual(TestMessage, Decrypted),

            io:format("✓ ~p-bit key test passed (actual: ~p bits)~n", [KeySize, ModulusBitSize])

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
        {ok, {PublicKey, PrivateKey}} = keylara_rsa:generate_keypair(NetPid, 1024),

        % Test 1: Message too large for RSA encryption
        TooLargeMessage = crypto:strong_rand_bytes(200), % Too large for 1024-bit key
        EncryptResult = keylara_rsa:encrypt(TooLargeMessage, PublicKey),
        ?assertMatch({error, _}, EncryptResult),
        io:format("✓ Large message error handling: OK~n"),

        % Test 2: Invalid encrypted data for decryption
        InvalidEncrypted = <<"invalid encrypted data">>,
        DecryptResult = keylara_rsa:decrypt(InvalidEncrypted, PrivateKey),
        ?assertMatch({error, _}, DecryptResult),
        io:format("✓ Invalid encrypted data error handling: OK~n"),

        % Test 3: Wrong key for decryption
        {ok, {_PublicKey2, PrivateKey2}} = keylara_rsa:generate_keypair(NetPid, 1024),
        TestMessage = <<"Test message">>,
        {ok, Encrypted} = keylara_rsa:encrypt(TestMessage, PublicKey),
        WrongKeyResult = keylara_rsa:decrypt(Encrypted, PrivateKey2),
        ?assertMatch({error, _}, WrongKeyResult),
        io:format("✓ Wrong key error handling: OK~n"),

        % Test 4: Non-binary input for encryption (should be handled by keylara_rsa)
        ListMessage = "Hello, World!",
        {ok, _} = keylara_rsa:encrypt(ListMessage, PublicKey), % Should convert to binary
        io:format("✓ List to binary conversion: OK~n"),

        % Test 5: Invalid key sizes
        InvalidKeySizeResult = keylara_rsa:generate_keypair(NetPid, 512),
        ?assertMatch({error, _}, InvalidKeySizeResult),
        io:format("✓ Invalid key size error handling: OK~n")

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

        % Generate very little entropy (not enough for RSA)
        SmallEntropy = [rand:uniform(2) =:= 1 || _ <- lists:seq(1, 100)],
        alara:generate_entropy(NetPid, {1, SmallEntropy}),
        timer:sleep(50),

        % Try to generate keypair - should fail
        Result = keylara_rsa:generate_keypair(NetPid, 1024),
        ?assertMatch({error, {entropy_generation_failed, _}}, Result),
        io:format("✓ Insufficient entropy detection: OK~n")

    after
        cleanup_network(NetPid)
    end,

    % Test 2: Adequate entropy
    {ok, NetPid2} = setup_test_network(4096), % Plenty of entropy

    try
        Result2 = keylara_rsa:generate_keypair(NetPid2, 1024),
        ?assertMatch({ok, _}, Result2),
        io:format("✓ Adequate entropy generation: OK~n")

    after
        cleanup_network(NetPid2)
    end,

    io:format("✓ Entropy requirements test passed~n").

%% @doc Test key consistency across multiple generations
test_key_consistency() ->
    io:format("Testing key consistency...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        % Generate multiple keypairs and verify they're different
        Keys = [begin
            {ok, KeyPair} = keylara_rsa:generate_keypair(NetPid, 1024),
            KeyPair
        end || _ <- lists:seq(1, 3)],

        % Verify all keys are different
        [{PublicKey1, _}, {PublicKey2, _}, {PublicKey3, _}] = Keys,

        ?assertNotEqual(PublicKey1#'RSAPublicKey'.modulus,
                        PublicKey2#'RSAPublicKey'.modulus),
        ?assertNotEqual(PublicKey2#'RSAPublicKey'.modulus,
                        PublicKey3#'RSAPublicKey'.modulus),
        ?assertNotEqual(PublicKey1#'RSAPublicKey'.modulus,
                        PublicKey3#'RSAPublicKey'.modulus),

        io:format("✓ Key uniqueness verified~n"),

        % Test encryption/decryption with each keypair
        TestMessage = <<"Consistency test message">>,

        lists:foreach(fun({PublicKey, PrivateKey}) ->
            {ok, Encrypted} = keylara_rsa:encrypt(TestMessage, PublicKey),
            {ok, Decrypted} = keylara_rsa:decrypt(Encrypted, PrivateKey),
            ?assertEqual(TestMessage, Decrypted)
        end, Keys),

        io:format("✓ Key functionality verified~n")

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Key consistency test passed~n").

%% @doc Test concurrent operations to ensure thread safety
test_concurrent_operations() ->
    io:format("Testing concurrent operations...~n"),

    {ok, NetPid} = setup_test_network(8192), % Extra entropy for concurrent access

    try
        % Generate a keypair for shared use
        {ok, {PublicKey, PrivateKey}} = keylara_rsa:generate_keypair(NetPid, 1024),

        % Create multiple concurrent encryption/decryption operations
        NumProcesses = 5,
        TestMessage = <<"Concurrent test message">>,

        Parent = self(),

        % Spawn concurrent processes
        Pids = [spawn(fun() ->
            try
                % Each process performs encryption/decryption
                {ok, Encrypted} = keylara_rsa:encrypt(TestMessage, PublicKey),
                {ok, Decrypted} = keylara_rsa:decrypt(Encrypted, PrivateKey),
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
    io:format("Running performance tests...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        % Benchmark key generation
        KeyGenStart = erlang:monotonic_time(microsecond),
        {ok, {PublicKey, PrivateKey}} = keylara_rsa:generate_keypair(NetPid, 1024),
        KeyGenTime = erlang:monotonic_time(microsecond) - KeyGenStart,

        io:format("Key generation time: ~p μs (~.2f ms)~n",
                 [KeyGenTime, KeyGenTime / 1000]),

        % Benchmark encryption/decryption
        TestMessage = <<"Performance test message for KeyLara benchmarking">>,
        NumIterations = 10,

        % Encryption benchmark
        EncStart = erlang:monotonic_time(microsecond),
        EncResults = [keylara_rsa:encrypt(TestMessage, PublicKey) || _ <- lists:seq(1, NumIterations)],
        EncTime = erlang:monotonic_time(microsecond) - EncStart,

        % Verify all encryptions succeeded
        lists:foreach(fun(Result) ->
            ?assertMatch({ok, _}, Result)
        end, EncResults),

        io:format("~p encryptions: ~p μs (~.2f ms avg)~n",
                 [NumIterations, EncTime, EncTime / NumIterations / 1000]),

        % Decryption benchmark
        [{ok, SampleEncrypted} | _] = EncResults,
        DecStart = erlang:monotonic_time(microsecond),
        DecResults = [keylara_rsa:decrypt(SampleEncrypted, PrivateKey) || _ <- lists:seq(1, NumIterations)],
        DecTime = erlang:monotonic_time(microsecond) - DecStart,

        % Verify all decryptions succeeded
        lists:foreach(fun(Result) ->
            ?assertMatch({ok, TestMessage}, Result)
        end, DecResults),

        io:format("~p decryptions: ~p μs (~.2f ms avg)~n",
                 [NumIterations, DecTime, DecTime / NumIterations / 1000])

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Performance tests completed~n").

%%%===================================================================
%%% Additional Tests for KeyLara Simplified API
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
    io:format("Testing default key size generation...~n"),
    
    {ok, NetPid} = setup_test_network(),
    
    try
        % Test default key size (should be 2048)
        {ok, {PublicKey, _PrivateKey}} = keylara:generate_keypair(NetPid),
        
        % Verify it's approximately 2048 bits
        Modulus = PublicKey#'RSAPublicKey'.modulus,
        ModulusBitSize = integer_bit_size(Modulus),
        
        ?assert(ModulusBitSize >= 2040),
        ?assert(ModulusBitSize =< 2056),
        
        io:format("✓ Default key size test passed (actual: ~p bits)~n", [ModulusBitSize])
        
    after
        cleanup_network(NetPid)
    end.

%%%===================================================================
%%% Test Runners
%%%===================================================================

%% @doc Run all tests
run_all_tests() ->
    io:format("~n=== Running KeyLara Complete Test Suite ===~n"),
    eunit:test(?MODULE, [verbose]).

%% @doc Run only basic functionality tests
run_basic_tests() ->
    io:format("~n=== Running Basic KeyLara Tests ===~n"),
    Tests = [
        fun test_basic_keypair_generation/0,
        fun test_encryption_decryption_cycle/0,
        fun test_multiple_message_sizes/0,
        fun test_default_key_generation/0,
        fun test_keylara_utilities/0
    ],
    run_test_list(Tests).

%% @doc Run advanced tests
run_advanced_tests() ->
    io:format("~n=== Running Advanced KeyLara Tests ===~n"),
    Tests = [
        fun test_different_key_sizes/0,
        fun test_error_handling/0,
        fun test_entropy_requirements/0,
        fun test_key_consistency/0,
        fun test_concurrent_operations/0
    ],
    run_test_list(Tests).

%% @doc Run performance tests
run_performance_tests() ->
    io:format("~n=== Running KeyLara Performance Tests ===~n"),
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
    setup_test_network(4096).

%% @doc Set up a test network with specified entropy amount
setup_test_network(EntropyBits) ->
    {ok, NetPid} = alara:create_network(),

    % Calculate how many nodes we need
    BitsPerNode = 1024,
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
%%    keylara_rsa_tests:run_all_tests().
%%
%% 2. Run specific test categories:
%%    keylara_rsa_tests:run_basic_tests().
%%    keylara_rsa_tests:run_advanced_tests().
%%    keylara_rsa_tests:run_performance_tests().
%%
%% 3. Use EUnit directly:
%%    eunit:test(keylara_rsa_tests).
%%
%% 4. Run with verbose output:
%%    eunit:test(keylara_rsa_tests, [verbose]).

%%%===================================================================
%%% End of Tests
%%%===================================================================
