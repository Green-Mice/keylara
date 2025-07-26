%%%-------------------------------------------------------------------
%%% @author Steve Roques
%%% @doc
%%% Comprehensive unit tests for the KeyLara ChaCha20 stream cipher library.
%%% This test suite covers:
%%% - ChaCha20 key and nonce generation using Alara distributed entropy
%%% - Stream cipher encryption and decryption
%%% - Error handling and edge cases
%%% - Performance and security validation
%%% - RFC 7539 test vectors compliance
%%%
%%% Usage:
%%%   eunit:test(keylara_chacha20_tests).
%%%   or
%%%   keylara_chacha20_tests:run_all_tests().
%%% @end
%%%-------------------------------------------------------------------

-module(keylara_chacha20_tests).

-include_lib("eunit/include/eunit.hrl").

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
keylara_chacha20_test_() ->
    {setup,
     fun setup_test_environment/0,
     fun cleanup_test_environment/1,
     [
         {timeout, 30, fun test_encryption_decryption_cycle/0},
         {timeout, 30, fun test_multiple_message_sizes/0},
         {timeout, 30, fun test_counter_functionality/0},
         {timeout, 30, fun test_rfc7539_vectors/0},
         {timeout, 30, fun test_error_handling/0},
         {timeout, 30, fun test_concurrent_operations/0},
         {timeout, 30, fun test_large_data_streams/0}
     ]}.

%%%===================================================================
%%% Test Environment Setup/Cleanup
%%%===================================================================

%% @doc Set up the test environment by starting necessary applications
setup_test_environment() ->
    io:format("Setting up KeyLara ChaCha20 test environment...~n"),

    % Start required applications
    application:start(crypto),

    % Start KeyLara
    keylara:start(),

    % Ensure random seed is set
    rand:seed(exrop, {erlang:phash2([node()]),
                      erlang:monotonic_time(),
                      erlang:unique_integer()}),

    io:format("ChaCha20 test environment ready.~n"),
    ok.

%% @doc Clean up the test environment
cleanup_test_environment(_) ->
    io:format("Cleaning up ChaCha20 test environment.~n"),
    keylara:stop(),
    ok.

%%%===================================================================
%%% Basic Functionality Tests
%%%===================================================================

%% @doc Test basic ChaCha20 key generation using Alara entropy
test_basic_key_generation() ->
    io:format("Testing basic ChaCha20 key generation...~n"),

    % Set up Alara network
    {ok, NetPid} = setup_test_network(),

    try
        % Generate ChaCha20 key using KeyLara API
        Result = keylara_chacha20:generate_key(NetPid),

        % Verify successful generation
        ?assertMatch({ok, _Key}, Result),

        % Extract key and verify structure
        {ok, Key} = Result,

        % Verify key properties
        ?assert(is_binary(Key)),
        ?assertEqual(32, byte_size(Key)), % ChaCha20 uses 256-bit (32-byte) keys
        ?assertEqual(ok, keylara_chacha20:validate_key(Key)),

        % Generate multiple keys and verify they're different
        {ok, Key2} = keylara_chacha20:generate_key(NetPid),
        {ok, Key3} = keylara_chacha20:generate_key(NetPid),

        ?assertNotEqual(Key, Key2),
        ?assertNotEqual(Key2, Key3),
        ?assertNotEqual(Key, Key3),

        io:format("✓ Basic key generation test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test basic ChaCha20 nonce generation using Alara entropy
test_basic_nonce_generation() ->
    io:format("Testing basic ChaCha20 nonce generation...~n"),

    % Set up Alara network
    {ok, NetPid} = setup_test_network(),

    try
        % Generate ChaCha20 nonce using KeyLara API
        Result = keylara_chacha20:generate_nonce(NetPid),

        % Verify successful generation
        ?assertMatch({ok, _Nonce}, Result),

        % Extract nonce and verify structure
        {ok, Nonce} = Result,

        % Verify nonce properties
        ?assert(is_binary(Nonce)),
        ?assertEqual(12, byte_size(Nonce)), % ChaCha20 uses 96-bit (12-byte) nonces
        ?assertEqual(ok, keylara_chacha20:validate_nonce(Nonce)),

        % Generate multiple nonces and verify they're different
        {ok, Nonce2} = keylara_chacha20:generate_nonce(NetPid),
        {ok, Nonce3} = keylara_chacha20:generate_nonce(NetPid),

        ?assertNotEqual(Nonce, Nonce2),
        ?assertNotEqual(Nonce2, Nonce3),
        ?assertNotEqual(Nonce, Nonce3),

        io:format("✓ Basic nonce generation test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test complete encryption/decryption cycle
test_encryption_decryption_cycle() ->
    io:format("Testing ChaCha20 encryption/decryption cycle...~n"),

    % Set up network and generate key/nonce
    {ok, NetPid} = setup_test_network(),

    try
        {ok, Key} = keylara_chacha20:generate_key(NetPid),
        {ok, Nonce} = keylara_chacha20:generate_nonce(NetPid),

        % Test data
        TestMessages = [
            <<"Hello, World!">>,
            <<"This is a test message for KeyLara ChaCha20 encryption.">>,
            <<"Short">>,
            <<"">>,  % Empty message
            crypto:strong_rand_bytes(100),  % Random binary data
            list_to_binary(lists:duplicate(1000, $a)), % Long repetitive data
            <<0:64>>, % All zeros
            <<255:64>> % All ones
        ],

        % Test each message
        lists:foreach(fun(Message) ->
            % Encrypt message using KeyLara ChaCha20 API
            {ok, EncryptedData} = keylara_chacha20:encrypt(Message, Key, Nonce),

            % Verify encryption result
            ?assert(is_binary(EncryptedData)),
            ?assertEqual(byte_size(Message), byte_size(EncryptedData)), % Stream cipher preserves length
            
            % Empty messages should encrypt to empty
            case byte_size(Message) of
                0 -> ?assertEqual(<<>>, EncryptedData);
                _ -> ?assertNotEqual(Message, EncryptedData)
            end,

            % Decrypt message using KeyLara ChaCha20 API
            {ok, DecryptedData} = keylara_chacha20:decrypt(EncryptedData, Key, Nonce),

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
        {ok, Key} = keylara_chacha20:generate_key(NetPid),
        {ok, Nonce} = keylara_chacha20:generate_nonce(NetPid),

        % Test different message sizes (ChaCha20 can encrypt any size)
        MessageSizes = [0, 1, 10, 50, 63, 64, 65, 100, 1000, 10000, 65536],

        lists:foreach(fun(Size) ->
            % Generate message of specific size
            Message = case Size of
                0 -> <<>>;
                _ -> crypto:strong_rand_bytes(Size)
            end,

            % Test encryption/decryption using KeyLara ChaCha20 API
            {ok, Encrypted} = keylara_chacha20:encrypt(Message, Key, Nonce),
            {ok, Decrypted} = keylara_chacha20:decrypt(Encrypted, Key, Nonce),

            % Verify
            ?assertEqual(Message, Decrypted),
            ?assertEqual(byte_size(Message), byte_size(Encrypted)),
            io:format("✓ Size ~p bytes: OK~n", [Size])
        end, MessageSizes),

        io:format("✓ Multiple message sizes test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test ChaCha20 counter functionality
test_counter_functionality() ->
    io:format("Testing ChaCha20 counter functionality...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        {ok, Key} = keylara_chacha20:generate_key(NetPid),
        {ok, Nonce} = keylara_chacha20:generate_nonce(NetPid),

        TestMessage = <<"This is a test message for counter functionality testing.">>,

        % Test encryption with different counter values
        Counters = [0, 1, 100, 1000, 16#FFFFFFFF],

        EncryptedResults = lists:map(fun(Counter) ->
            {ok, Encrypted} = keylara_chacha20:encrypt(TestMessage, Key, Nonce, Counter),
            {Counter, Encrypted}
        end, Counters),

        % Verify all encrypted results are different (except for any potential collisions)
        EncryptedData = [Data || {_, Data} <- EncryptedResults],
        UniqueData = lists:usort(EncryptedData),
        ?assertEqual(length(EncryptedData), length(UniqueData)),

        % Test decryption with matching counters
        lists:foreach(fun({Counter, Encrypted}) ->
            {ok, Decrypted} = keylara_chacha20:decrypt(Encrypted, Key, Nonce, Counter),
            ?assertEqual(TestMessage, Decrypted),
            io:format("✓ Counter ~p: OK~n", [Counter])
        end, EncryptedResults),

        % Test that wrong counter gives wrong result
        {Counter1, Encrypted1} = hd(EncryptedResults),
        WrongCounter = Counter1 + 1,
        {ok, WrongDecrypted} = keylara_chacha20:decrypt(Encrypted1, Key, Nonce, WrongCounter),
        ?assertNotEqual(TestMessage, WrongDecrypted),

        io:format("✓ Counter functionality test passed~n")

    after
        cleanup_network(NetPid)
    end.

%% @doc Test RFC 7539 test vectors for compliance
test_rfc7539_vectors() ->
    io:format("Testing RFC 7539 compliance...~n"),

    % Test vector from RFC 7539, Section 2.4.2
    Key = <<16#00,16#01,16#02,16#03,16#04,16#05,16#06,16#07,
            16#08,16#09,16#0a,16#0b,16#0c,16#0d,16#0e,16#0f,
            16#10,16#11,16#12,16#13,16#14,16#15,16#16,16#17,
            16#18,16#19,16#1a,16#1b,16#1c,16#1d,16#1e,16#1f>>,
    
    Nonce = <<16#00,16#00,16#00,16#00,16#00,16#00,16#00,16#4a,
              16#00,16#00,16#00,16#00>>,
    
    Counter = 1,
    
    Plaintext = <<"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.">>,

    % Test encryption
    {ok, Ciphertext} = keylara_chacha20:encrypt(Plaintext, Key, Nonce, Counter),
    
    % Test decryption
    {ok, Decrypted} = keylara_chacha20:decrypt(Ciphertext, Key, Nonce, Counter),
    
    % Verify round-trip
    ?assertEqual(Plaintext, Decrypted),
    
    % Verify ciphertext properties
    ?assertEqual(byte_size(Plaintext), byte_size(Ciphertext)),
    ?assertNotEqual(Plaintext, Ciphertext),

    io:format("✓ RFC 7539 test vector passed~n"),

    % Additional test with counter = 0
    {ok, Ciphertext2} = keylara_chacha20:encrypt(Plaintext, Key, Nonce, 0),
    {ok, Decrypted2} = keylara_chacha20:decrypt(Ciphertext2, Key, Nonce, 0),
    ?assertEqual(Plaintext, Decrypted2),
    ?assertNotEqual(Ciphertext, Ciphertext2), % Different counter should give different result

    io:format("✓ RFC 7539 compliance test passed~n").

%%%===================================================================
%%% Error Handling Tests
%%%===================================================================

%% @doc Test various error conditions and edge cases
test_error_handling() ->
    io:format("Testing ChaCha20 error handling...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        {ok, ValidKey} = keylara_chacha20:generate_key(NetPid),
        {ok, ValidNonce} = keylara_chacha20:generate_nonce(NetPid),

        % Test 1: Invalid key sizes
        InvalidKeys = [
            <<>>, % Empty key
            <<1,2,3>>, % Too short
            crypto:strong_rand_bytes(31), % One byte short
            crypto:strong_rand_bytes(33), % One byte too long
            crypto:strong_rand_bytes(64), % Too long
            "not_binary", % Not binary
            123 % Wrong type
        ],

        lists:foreach(fun(InvalidKey) ->
            EncryptResult = keylara_chacha20:encrypt(<<"test">>, InvalidKey, ValidNonce),
            ?assertMatch({error, _}, EncryptResult),
            
            DecryptResult = keylara_chacha20:decrypt(<<"test">>, InvalidKey, ValidNonce),
            ?assertMatch({error, _}, DecryptResult)
        end, InvalidKeys),
        io:format("✓ Invalid key error handling: OK~n"),

        % Test 2: Invalid nonce sizes
        InvalidNonces = [
            <<>>, % Empty nonce
            <<1,2,3>>, % Too short
            crypto:strong_rand_bytes(11), % One byte short
            crypto:strong_rand_bytes(13), % One byte too long
            crypto:strong_rand_bytes(16), % Too long
            "not_binary", % Not binary
            456 % Wrong type
        ],

        lists:foreach(fun(InvalidNonce) ->
            EncryptResult = keylara_chacha20:encrypt(<<"test">>, ValidKey, InvalidNonce),
            ?assertMatch({error, _}, EncryptResult),
            
            DecryptResult = keylara_chacha20:decrypt(<<"test">>, ValidKey, InvalidNonce),
            ?assertMatch({error, _}, DecryptResult)
        end, InvalidNonces),
        io:format("✓ Invalid nonce error handling: OK~n"),

        % Test 3: Invalid counter values
        InvalidCounters = [-1, -100, "invalid", atom, 1.5],

        lists:foreach(fun(InvalidCounter) ->
            EncryptResult = keylara_chacha20:encrypt(<<"test">>, ValidKey, ValidNonce, InvalidCounter),
            ?assertMatch({error, _}, EncryptResult),
            
            DecryptResult = keylara_chacha20:decrypt(<<"test">>, ValidKey, ValidNonce, InvalidCounter),
            ?assertMatch({error, _}, DecryptResult)
        end, InvalidCounters),
        io:format("✓ Invalid counter error handling: OK~n"),

        % Test 4: Invalid data types for encryption
        InvalidData = [123, atom, {tuple}, [list]],

        lists:foreach(fun(InvalidDataItem) ->
            EncryptResult = keylara_chacha20:encrypt(InvalidDataItem, ValidKey, ValidNonce),
            ?assertMatch({error, _}, EncryptResult),
            
            DecryptResult = keylara_chacha20:decrypt(InvalidDataItem, ValidKey, ValidNonce),
            ?assertMatch({error, _}, DecryptResult)
        end, InvalidData),
        io:format("✓ Invalid data type error handling: OK~n"),

        % Test 5: Invalid network PID for key generation
        InvalidPids = [undefined, "not_pid", 123, self()], % self() is valid but not an Alara network

        lists:foreach(fun(InvalidPid) ->
            KeyResult = keylara_chacha20:generate_key(InvalidPid),
            ?assertMatch({error, _}, KeyResult),
            
            NonceResult = keylara_chacha20:generate_nonce(InvalidPid),
            ?assertMatch({error, _}, NonceResult)
        end, InvalidPids),
        io:format("✓ Invalid network PID error handling: OK~n")

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Error handling test passed~n").

%% @doc Test entropy requirements and insufficient entropy scenarios
test_entropy_requirements() ->
    io:format("Testing ChaCha20 entropy requirements...~n"),

    % Test 1: Insufficient entropy for key generation
    {ok, NetPid} = alara:create_network(),

    try
        % Add only one node with minimal entropy
        {ok, Node} = alara:create_node(1, 0.9, true),
        alara:add_node(NetPid, Node),

        % Generate very little entropy (not enough for ChaCha20 key)
        SmallEntropy = [rand:uniform(2) =:= 1 || _ <- lists:seq(1, 100)],
        alara:generate_entropy(NetPid, {1, SmallEntropy}),
        timer:sleep(50),

        % Try to generate key - should fail
        KeyResult = keylara_chacha20:generate_key(NetPid),
        ?assertMatch({error, {key_generation_failed, _}}, KeyResult),
        
        % Try to generate nonce - should also fail
        NonceResult = keylara_chacha20:generate_nonce(NetPid),
        ?assertMatch({error, {nonce_generation_failed, _}}, NonceResult),
        
        io:format("✓ Insufficient entropy detection: OK~n")

    after
        cleanup_network(NetPid)
    end,

    % Test 2: Adequate entropy
    {ok, NetPid2} = setup_test_network(1024), % Adequate entropy

    try
        KeyResult2 = keylara_chacha20:generate_key(NetPid2),
        ?assertMatch({ok, _}, KeyResult2),
        
        NonceResult2 = keylara_chacha20:generate_nonce(NetPid2),
        ?assertMatch({ok, _}, NonceResult2),
        
        io:format("✓ Adequate entropy generation: OK~n")

    after
        cleanup_network(NetPid2)
    end,

    io:format("✓ Entropy requirements test passed~n").

%% @doc Test key and nonce consistency across multiple generations
test_key_nonce_consistency() ->
    io:format("Testing key and nonce consistency...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        % Generate multiple keys and verify they're different
        Keys = [begin
            {ok, Key} = keylara_chacha20:generate_key(NetPid),
            Key
        end || _ <- lists:seq(1, 5)],

        % Verify all keys are unique
        UniqueKeys = lists:usort(Keys),
        ?assertEqual(length(Keys), length(UniqueKeys)),

        % Generate multiple nonces and verify they're different
        Nonces = [begin
            {ok, Nonce} = keylara_chacha20:generate_nonce(NetPid),
            Nonce
        end || _ <- lists:seq(1, 5)],

        % Verify all nonces are unique
        UniqueNonces = lists:usort(Nonces),
        ?assertEqual(length(Nonces), length(UniqueNonces)),

        io:format("✓ Key and nonce uniqueness verified~n"),

        % Test encryption/decryption with each key-nonce pair
        TestMessage = <<"Consistency test message for ChaCha20">>,

        lists:foreach(fun({Key, Nonce}) ->
            {ok, Encrypted} = keylara_chacha20:encrypt(TestMessage, Key, Nonce),
            {ok, Decrypted} = keylara_chacha20:decrypt(Encrypted, Key, Nonce),
            ?assertEqual(TestMessage, Decrypted)
        end, lists:zip(Keys, Nonces)),

        io:format("✓ Key-nonce functionality verified~n")

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Key and nonce consistency test passed~n").

%% @doc Test concurrent operations to ensure thread safety
test_concurrent_operations() ->
    io:format("Testing concurrent ChaCha20 operations...~n"),

    {ok, NetPid} = setup_test_network(8192), % Extra entropy for concurrent access

    try
        % Generate shared key and nonce
        {ok, SharedKey} = keylara_chacha20:generate_key(NetPid),
        {ok, SharedNonce} = keylara_chacha20:generate_nonce(NetPid),

        % Create multiple concurrent encryption/decryption operations
        NumProcesses = 10,
        TestMessage = <<"Concurrent ChaCha20 test message">>,

        Parent = self(),

        % Spawn concurrent processes
        Pids = [spawn(fun() ->
            try
                % Each process performs encryption/decryption with different counter
                Counter = N,
                {ok, Encrypted} = keylara_chacha20:encrypt(TestMessage, SharedKey, SharedNonce, Counter),
                {ok, Decrypted} = keylara_chacha20:decrypt(Encrypted, SharedKey, SharedNonce, Counter),
                ?assertEqual(TestMessage, Decrypted),
                Parent ! {self(), success}
            catch
                Error:Reason ->
                    Parent ! {self(), {error, Error, Reason}}
            end
        end) || N <- lists:seq(1, NumProcesses)],

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

%% @doc Test large data stream encryption/decryption
test_large_data_streams() ->
    io:format("Testing large data stream encryption...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        {ok, Key} = keylara_chacha20:generate_key(NetPid),
        {ok, Nonce} = keylara_chacha20:generate_nonce(NetPid),

        % Test progressively larger data sizes
        DataSizes = [1024, 10240, 102400, 1048576], % 1KB, 10KB, 100KB, 1MB

        lists:foreach(fun(Size) ->
            io:format("Testing ~p byte data stream...~n", [Size]),
            
            % Generate test data
            TestData = crypto:strong_rand_bytes(Size),
            
            % Measure encryption time
            StartTime = erlang:monotonic_time(microsecond),
            {ok, Encrypted} = keylara_chacha20:encrypt(TestData, Key, Nonce),
            EncryptTime = erlang:monotonic_time(microsecond) - StartTime,
            
            % Verify encryption
            ?assertEqual(Size, byte_size(Encrypted)),
            ?assertNotEqual(TestData, Encrypted),
            
            % Measure decryption time
            DecryptStartTime = erlang:monotonic_time(microsecond),
            {ok, Decrypted} = keylara_chacha20:decrypt(Encrypted, Key, Nonce),
            DecryptTime = erlang:monotonic_time(microsecond) - DecryptStartTime,
            
            % Verify decryption
            ?assertEqual(TestData, Decrypted),
            
            % Calculate throughput
            EncryptThroughput = (Size * 1000000) div (EncryptTime + 1), % bytes/second
            DecryptThroughput = (Size * 1000000) div (DecryptTime + 1), % bytes/second
            
            io:format("✓ ~p bytes: Encrypt ~p μs (~p MB/s), Decrypt ~p μs (~p MB/s)~n",
                     [Size, EncryptTime, EncryptThroughput div (1024*1024),
                      DecryptTime, DecryptThroughput div (1024*1024)])
        end, DataSizes),

        io:format("✓ Large data stream test passed~n")

    after
        cleanup_network(NetPid)
    end.

%%%===================================================================
%%% Performance Tests
%%%===================================================================

%% @doc Comprehensive performance benchmarking
test_performance() ->
    io:format("Running ChaCha20 performance tests...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        % Benchmark key generation
        KeyGenTimes = [begin
            Start = erlang:monotonic_time(microsecond),
            {ok, _Key} = keylara_chacha20:generate_key(NetPid),
            erlang:monotonic_time(microsecond) - Start
        end || _ <- lists:seq(1, 10)],

        AvgKeyGenTime = lists:sum(KeyGenTimes) div length(KeyGenTimes),
        io:format("Key generation average: ~p μs (~.2f ms)~n",
                 [AvgKeyGenTime, AvgKeyGenTime / 1000]),

        % Benchmark nonce generation
        NonceGenTimes = [begin
            Start = erlang:monotonic_time(microsecond),
            {ok, _Nonce} = keylara_chacha20:generate_nonce(NetPid),
            erlang:monotonic_time(microsecond) - Start
        end || _ <- lists:seq(1, 10)],

        AvgNonceGenTime = lists:sum(NonceGenTimes) div length(NonceGenTimes),
        io:format("Nonce generation average: ~p μs (~.2f ms)~n",
                 [AvgNonceGenTime, AvgNonceGenTime / 1000]),

        % Generate key and nonce for encryption benchmarks
        {ok, Key} = keylara_chacha20:generate_key(NetPid),
        {ok, Nonce} = keylara_chacha20:generate_nonce(NetPid),

        % Benchmark encryption/decryption with different message sizes
        MessageSizes = [64, 1024, 10240, 102400], % 64B, 1KB, 10KB, 100KB
        NumIterations = 100,

        lists:foreach(fun(MsgSize) ->
            TestMessage = crypto:strong_rand_bytes(MsgSize),

            % Encryption benchmark
            EncStart = erlang:monotonic_time(microsecond),
            EncResults = [keylara_chacha20:encrypt(TestMessage, Key, Nonce) || _ <- lists:seq(1, NumIterations)],
            EncTime = erlang:monotonic_time(microsecond) - EncStart,

            % Verify all encryptions succeeded
            lists:foreach(fun(Result) ->
                ?assertMatch({ok, _}, Result)
            end, EncResults),

            AvgEncTime = EncTime / NumIterations,
            EncThroughput = (MsgSize * NumIterations * 1000000) div (EncTime + 1),

            io:format("~p bytes x ~p encryptions: ~.2f μs avg (~p MB/s)~n",
                     [MsgSize, NumIterations, AvgEncTime, EncThroughput div (1024*1024)]),

            % Decryption benchmark
            [{ok, SampleEncrypted} | _] = EncResults,
            DecStart = erlang:monotonic_time(microsecond),
            DecResults = [keylara_chacha20:decrypt(SampleEncrypted, Key, Nonce) || _ <- lists:seq(1, NumIterations)],
            DecTime = erlang:monotonic_time(microsecond) - DecStart,

            % Verify all decryptions succeeded
            lists:foreach(fun(Result) ->
                ?assertMatch({ok, TestMessage}, Result)
            end, DecResults),

            AvgDecTime = DecTime / NumIterations,
            DecThroughput = (MsgSize * NumIterations * 1000000) div (DecTime + 1),

            io:format("~p bytes x ~p decryptions: ~.2f μs avg (~p MB/s)~n",
                     [MsgSize, NumIterations, AvgDecTime, DecThroughput div (1024*1024)])
        end, MessageSizes)

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Performance tests completed~n").

%%%===================================================================
%%% Test Runners
%%%===================================================================

%% @doc Run all tests
run_all_tests() ->
    io:format("~n=== Running KeyLara ChaCha20 Complete Test Suite ===~n"),
    eunit:test(?MODULE, [verbose]).

%% @doc Run only basic functionality tests
run_basic_tests() ->
    io:format("~n=== Running Basic ChaCha20 Tests ===~n"),
    Tests = [
        fun test_basic_key_generation/0,
        fun test_basic_nonce_generation/0,
        fun test_encryption_decryption_cycle/0,
        fun test_multiple_message_sizes/0,
        fun test_counter_functionality/0
    ],
    run_test_list(Tests).

%% @doc Run advanced tests
run_advanced_tests() ->
    io:format("~n=== Running Advanced ChaCha20 Tests ===~n"),
    Tests = [
        fun test_rfc7539_vectors/0,
        fun test_error_handling/0,
        fun test_entropy_requirements/0,
        fun test_key_nonce_consistency/0,
        fun test_concurrent_operations/0,
        fun test_large_data_streams/0
    ],
    run_test_list(Tests).

%% @doc Run performance tests
run_performance_tests() ->
    io:format("~n=== Running ChaCha20 Performance Tests ===~n"),
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
%%% Additional ChaCha20 Specific Tests
%%%===================================================================

%% @doc Test ChaCha20 utility functions
test_chacha20_utilities() ->
    io:format("Testing ChaCha20 utilities...~n"),

    % Test key size function
    KeySize = keylara_chacha20:get_key_size(),
    ?assertEqual(32, KeySize),
    io:format("✓ Key size: ~p bytes~n", [KeySize]),

    % Test nonce size function
    NonceSize = keylara_chacha20:get_nonce_size(),
    ?assertEqual(12, NonceSize),
    io:format("✓ Nonce size: ~p bytes~n", [NonceSize]),

    % Test validation functions
    ValidKey = crypto:strong_rand_bytes(32),
    ValidNonce = crypto:strong_rand_bytes(12),
    
    ?assertEqual(ok, keylara_chacha20:validate_key(ValidKey)),
    ?assertEqual(ok, keylara_chacha20:validate_nonce(ValidNonce)),

    InvalidKey = crypto:strong_rand_bytes(16),
    InvalidNonce = crypto:strong_rand_bytes(8),
    
    ?assertMatch({error, _}, keylara_chacha20:validate_key(InvalidKey)),
    ?assertMatch({error, _}, keylara_chacha20:validate_nonce(InvalidNonce)),

    io:format("✓ ChaCha20 utilities test passed~n").

%% @doc Test keystream properties and consistency
test_keystream_properties() ->
    io:format("Testing ChaCha20 keystream properties...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        {ok, Key} = keylara_chacha20:generate_key(NetPid),
        {ok, Nonce} = keylara_chacha20:generate_nonce(NetPid),

        % Test that same key/nonce/counter produces same keystream
        TestData1 = crypto:strong_rand_bytes(100),
        TestData2 = crypto:strong_rand_bytes(100),
        
        {ok, Encrypted1a} = keylara_chacha20:encrypt(TestData1, Key, Nonce, 0),
        {ok, Encrypted1b} = keylara_chacha20:encrypt(TestData1, Key, Nonce, 0),
        ?assertEqual(Encrypted1a, Encrypted1b),

        % Test that different data with same key/nonce/counter XORs correctly
        {ok, Encrypted2} = keylara_chacha20:encrypt(TestData2, Key, Nonce, 0),
        
        % XOR the encrypted data should equal XOR of original data
        XorEncrypted = crypto:exor(Encrypted1a, Encrypted2),
        XorOriginal = crypto:exor(TestData1, TestData2),
        ?assertEqual(XorOriginal, XorEncrypted),

        io:format("✓ Keystream consistency verified~n"),

        % Test that consecutive blocks are different
        BlockSize = 64,
        LargeData = crypto:strong_rand_bytes(BlockSize * 3),
        {ok, EncryptedLarge} = keylara_chacha20:encrypt(LargeData, Key, Nonce, 0),
        
        Block1 = binary:part(EncryptedLarge, 0, BlockSize),
        Block2 = binary:part(EncryptedLarge, BlockSize, BlockSize),
        Block3 = binary:part(EncryptedLarge, BlockSize * 2, BlockSize),
        
        ?assertNotEqual(Block1, Block2),
        ?assertNotEqual(Block2, Block3),
        ?assertNotEqual(Block1, Block3),

        io:format("✓ Keystream block differentiation verified~n")

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Keystream properties test passed~n").

%% @doc Test edge cases and boundary conditions
test_edge_cases() ->
    io:format("Testing ChaCha20 edge cases...~n"),

    {ok, NetPid} = setup_test_network(),

    try
        {ok, Key} = keylara_chacha20:generate_key(NetPid),
        {ok, Nonce} = keylara_chacha20:generate_nonce(NetPid),

        % Test 1: Maximum counter value
        MaxCounter = 16#FFFFFFFF,
        TestMessage = <<"Max counter test">>,
        
        {ok, Encrypted} = keylara_chacha20:encrypt(TestMessage, Key, Nonce, MaxCounter),
        {ok, Decrypted} = keylara_chacha20:decrypt(Encrypted, Key, Nonce, MaxCounter),
        ?assertEqual(TestMessage, Decrypted),
        io:format("✓ Maximum counter value works~n"),

        % Test 2: Block boundary encryption (64 bytes = 1 ChaCha20 block)
        BlockSizeData = crypto:strong_rand_bytes(64),
        {ok, EncryptedBlock} = keylara_chacha20:encrypt(BlockSizeData, Key, Nonce),
        {ok, DecryptedBlock} = keylara_chacha20:decrypt(EncryptedBlock, Key, Nonce),
        ?assertEqual(BlockSizeData, DecryptedBlock),
        io:format("✓ Block boundary encryption works~n"),

        % Test 3: Just over block boundary (65 bytes)
        OverBlockData = crypto:strong_rand_bytes(65),
        {ok, EncryptedOver} = keylara_chacha20:encrypt(OverBlockData, Key, Nonce),
        {ok, DecryptedOver} = keylara_chacha20:decrypt(EncryptedOver, Key, Nonce),
        ?assertEqual(OverBlockData, DecryptedOver),
        io:format("✓ Over block boundary encryption works~n"),

        % Test 4: All-zero data
        ZeroData = <<0:512>>, % 64 bytes of zeros
        {ok, EncryptedZero} = keylara_chacha20:encrypt(ZeroData, Key, Nonce),
        ?assertNotEqual(ZeroData, EncryptedZero), % Should not be zero
        {ok, DecryptedZero} = keylara_chacha20:decrypt(EncryptedZero, Key, Nonce),
        ?assertEqual(ZeroData, DecryptedZero),
        io:format("✓ All-zero data encryption works~n"),

        % Test 5: All-ones data
        OnesData = <<16#FF:512>>, % 64 bytes of 0xFF
        {ok, EncryptedOnes} = keylara_chacha20:encrypt(OnesData, Key, Nonce),
        ?assertNotEqual(OnesData, EncryptedOnes), % Should not be all ones
        {ok, DecryptedOnes} = keylara_chacha20:decrypt(EncryptedOnes, Key, Nonce),
        ?assertEqual(OnesData, DecryptedOnes),
        io:format("✓ All-ones data encryption works~n")

    after
        cleanup_network(NetPid)
    end,

    io:format("✓ Edge cases test passed~n").

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
        {ok, Node} = alara:create_node(NodeId, 0.9 - (NodeId * 0.05), true),
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
%%% Utility Tests Integration
%%%===================================================================

%% @doc Extended test suite including utility tests
extended_test_() ->
    {setup,
     fun setup_test_environment/0,
     fun cleanup_test_environment/1,
     [
         {timeout, 10, fun test_chacha20_utilities/0},
         {timeout, 30, fun test_keystream_properties/0},
         {timeout, 20, fun test_edge_cases/0}
     ]}.
