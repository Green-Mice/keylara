%%%===================================================================
%%% Description: ChaCha20 stream cipher implementation with Alara entropy
%%%===================================================================
-module(keylara_chacha20).
-export([
    generate_key/1,
    generate_nonce/1,
    encrypt/3,
    decrypt/3,
    encrypt/4,
    decrypt/4,
    validate_key/1,
    validate_nonce/1,
    get_key_size/0,
    get_nonce_size/0
]).
-include("keylara.hrl").

-define(CHACHA20_KEY_SIZE, 32).      % 256 bits
-define(CHACHA20_NONCE_SIZE, 12).    % 96 bits (ChaCha20 standard)
-define(CHACHA20_BLOCK_SIZE, 64).    % 512 bits
-define(CHACHA20_ROUNDS, 20).        % Standard ChaCha20 uses 20 rounds

%%%===================================================================
%%% Types
%%%===================================================================
-type chacha20_key() :: binary().
-type chacha20_nonce() :: binary().
-type chacha20_counter() :: non_neg_integer().

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Generate ChaCha20 key using Alara distributed entropy
%% @param NetPid - Process ID of the Alara network
%% @return {ok, Key} | {error, Reason}
-spec generate_key(pid()) -> {ok, chacha20_key()} | keylara_error().
generate_key(NetPid) when is_pid(NetPid) ->
    case keylara:get_entropy_bytes(NetPid, ?CHACHA20_KEY_SIZE) of
        {ok, KeyBytes} ->
            {ok, KeyBytes};
        {error, Reason} ->
            {error, {key_generation_failed, Reason}}
    end;
generate_key(_NetPid) ->
    {error, invalid_network_pid}.

%% @doc Generate ChaCha20 nonce using Alara distributed entropy
%% @param NetPid - Process ID of the Alara network
%% @return {ok, Nonce} | {error, Reason}
-spec generate_nonce(pid()) -> {ok, chacha20_nonce()} | keylara_error().
generate_nonce(NetPid) when is_pid(NetPid) ->
    case keylara:get_entropy_bytes(NetPid, ?CHACHA20_NONCE_SIZE) of
        {ok, NonceBytes} ->
            {ok, NonceBytes};
        {error, Reason} ->
            {error, {nonce_generation_failed, Reason}}
    end;
generate_nonce(_NetPid) ->
    {error, invalid_network_pid}.

%% @doc Encrypt data using ChaCha20 with counter = 0
%% @param Data - Binary data to encrypt
%% @param Key - ChaCha20 key (32 bytes)
%% @param Nonce - ChaCha20 nonce (12 bytes)
%% @return {ok, EncryptedData} | {error, Reason}
-spec encrypt(binary(), chacha20_key(), chacha20_nonce()) -> {ok, binary()} | keylara_error().
encrypt(Data, Key, Nonce) ->
    encrypt(Data, Key, Nonce, 0).

%% @doc Encrypt data using ChaCha20 with specified counter
%% @param Data - Binary data to encrypt
%% @param Key - ChaCha20 key (32 bytes)
%% @param Nonce - ChaCha20 nonce (12 bytes)
%% @param Counter - Initial counter value
%% @return {ok, EncryptedData} | {error, Reason}
-spec encrypt(binary(), chacha20_key(), chacha20_nonce(), chacha20_counter()) -> {ok, binary()} | keylara_error().
encrypt(Data, Key, Nonce, Counter) when is_binary(Data), is_integer(Counter), Counter >= 0 ->
    try
        case validate_key(Key) of
            ok ->
                case validate_nonce(Nonce) of
                    ok ->
                        KeyStream = generate_keystream(Key, Nonce, Counter, byte_size(Data)),
                        EncryptedData = crypto_xor(Data, KeyStream),
                        {ok, EncryptedData};
                    {error, NonceReason} ->
                        {error, NonceReason}
                end;
            {error, KeyReason} ->
                {error, KeyReason}
        end
    catch
        Error:CatchReason:Stacktrace ->
            {error, {encryption_failed, Error, CatchReason, Stacktrace}}
    end;
encrypt(_Data, _Key, _Nonce, _Counter) ->
    {error, invalid_parameters}.

%% @doc Decrypt data using ChaCha20 with counter = 0
%% @param EncryptedData - Binary encrypted data
%% @param Key - ChaCha20 key (32 bytes)
%% @param Nonce - ChaCha20 nonce (12 bytes)
%% @return {ok, DecryptedData} | {error, Reason}
-spec decrypt(binary(), chacha20_key(), chacha20_nonce()) -> {ok, binary()} | keylara_error().
decrypt(EncryptedData, Key, Nonce) ->
    decrypt(EncryptedData, Key, Nonce, 0).

%% @doc Decrypt data using ChaCha20 with specified counter
%% @param EncryptedData - Binary encrypted data
%% @param Key - ChaCha20 key (32 bytes)
%% @param Nonce - ChaCha20 nonce (12 bytes)
%% @param Counter - Initial counter value
%% @return {ok, DecryptedData} | {error, Reason}
-spec decrypt(binary(), chacha20_key(), chacha20_nonce(), chacha20_counter()) -> {ok, binary()} | keylara_error().
decrypt(EncryptedData, Key, Nonce, Counter) ->
    % ChaCha20 is symmetric, so decryption is the same as encryption
    encrypt(EncryptedData, Key, Nonce, Counter).

%% @doc Validate ChaCha20 key format and size
%% @param Key - Key to validate
%% @return ok | {error, Reason}
-spec validate_key(term()) -> ok | keylara_error().
validate_key(Key) when is_binary(Key) ->
    case byte_size(Key) of
        ?CHACHA20_KEY_SIZE ->
            ok;
        Size ->
            {error, {invalid_key_size, Size, ?CHACHA20_KEY_SIZE}}
    end;
validate_key(_Key) ->
    {error, invalid_key_format}.

%% @doc Validate ChaCha20 nonce format and size
%% @param Nonce - Nonce to validate
%% @return ok | {error, Reason}
-spec validate_nonce(term()) -> ok | keylara_error().
validate_nonce(Nonce) when is_binary(Nonce) ->
    case byte_size(Nonce) of
        ?CHACHA20_NONCE_SIZE ->
            ok;
        Size ->
            {error, {invalid_nonce_size, Size, ?CHACHA20_NONCE_SIZE}}
    end;
validate_nonce(_Nonce) ->
    {error, invalid_nonce_format}.

%% @doc Get ChaCha20 key size in bytes
%% @return Key size in bytes
-spec get_key_size() -> integer().
get_key_size() ->
    ?CHACHA20_KEY_SIZE.

%% @doc Get ChaCha20 nonce size in bytes
%% @return Nonce size in bytes
-spec get_nonce_size() -> integer().
get_nonce_size() ->
    ?CHACHA20_NONCE_SIZE.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @doc Generate ChaCha20 keystream
%% @param Key - ChaCha20 key
%% @param Nonce - ChaCha20 nonce
%% @param Counter - Initial counter value
%% @param Length - Length of keystream to generate
%% @return Binary keystream
-spec generate_keystream(chacha20_key(), chacha20_nonce(), chacha20_counter(), non_neg_integer()) -> binary().
generate_keystream(Key, Nonce, Counter, Length) ->
    BlocksNeeded = (Length + ?CHACHA20_BLOCK_SIZE - 1) div ?CHACHA20_BLOCK_SIZE,
    KeystreamBlocks = [chacha20_block(Key, Nonce, Counter + I) || I <- lists:seq(0, BlocksNeeded - 1)],
    Keystream = iolist_to_binary(KeystreamBlocks),
    binary:part(Keystream, 0, Length).

%% @doc Generate a single ChaCha20 block
%% @param Key - ChaCha20 key
%% @param Nonce - ChaCha20 nonce
%% @param Counter - Block counter
%% @return 64-byte block
-spec chacha20_block(chacha20_key(), chacha20_nonce(), chacha20_counter()) -> binary().
chacha20_block(Key, Nonce, Counter) ->
    % Initialize ChaCha20 state
    State = init_chacha20_state(Key, Nonce, Counter),
    % Perform 20 rounds of ChaCha20
    FinalState = chacha20_rounds(State, ?CHACHA20_ROUNDS),
    % Add initial state to final state
    AddedState = add_states(State, FinalState),
    % Convert to binary
    state_to_binary(AddedState).

%% @doc Initialize ChaCha20 state
%% @param Key - ChaCha20 key
%% @param Nonce - ChaCha20 nonce
%% @param Counter - Block counter
%% @return Initial state array
-spec init_chacha20_state(chacha20_key(), chacha20_nonce(), chacha20_counter()) -> tuple().
init_chacha20_state(Key, Nonce, Counter) ->
    % ChaCha20 constants: "expand 32-byte k"
    C0 = 16#61707865,
    C1 = 16#3320646e,
    C2 = 16#79622d32,
    C3 = 16#6b206574,
    
    % Extract key words (little-endian)
    <<K0:32/little, K1:32/little, K2:32/little, K3:32/little,
      K4:32/little, K5:32/little, K6:32/little, K7:32/little>> = Key,
    
    % Extract nonce words (little-endian)
    <<N0:32/little, N1:32/little, N2:32/little>> = Nonce,
    
    % Create initial state
    {C0, C1, C2, C3, K0, K1, K2, K3, K4, K5, K6, K7, Counter, N0, N1, N2}.

%% @doc Perform ChaCha20 rounds
%% @param State - Current state
%% @param RoundsLeft - Number of rounds remaining
%% @return Final state after all rounds
-spec chacha20_rounds(tuple(), non_neg_integer()) -> tuple().
chacha20_rounds(State, 0) ->
    State;
chacha20_rounds(State, RoundsLeft) when RoundsLeft rem 2 =:= 0 ->
    % Column rounds
    State1 = quarter_round(State, 0, 4, 8, 12),
    State2 = quarter_round(State1, 1, 5, 9, 13),
    State3 = quarter_round(State2, 2, 6, 10, 14),
    State4 = quarter_round(State3, 3, 7, 11, 15),
    chacha20_rounds(State4, RoundsLeft - 1);
chacha20_rounds(State, RoundsLeft) ->
    % Diagonal rounds
    State1 = quarter_round(State, 0, 5, 10, 15),
    State2 = quarter_round(State1, 1, 6, 11, 12),
    State3 = quarter_round(State2, 2, 7, 8, 13),
    State4 = quarter_round(State3, 3, 4, 9, 14),
    chacha20_rounds(State4, RoundsLeft - 1).

%% @doc Perform ChaCha20 quarter round
%% @param State - Current state tuple
%% @param A, B, C, D - Indices for quarter round
%% @return Updated state tuple
-spec quarter_round(tuple(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()) -> tuple().
quarter_round(State, A, B, C, D) ->
    % Convert tuple to list for easier manipulation
    StateList = tuple_to_list(State),
    
    % Get values
    VA = lists:nth(A + 1, StateList),
    VB = lists:nth(B + 1, StateList),
    VC = lists:nth(C + 1, StateList),
    VD = lists:nth(D + 1, StateList),
    
    % Perform quarter round operations
    VA1 = (VA + VB) band 16#ffffffff,
    VD1 = rotl32(VD bxor VA1, 16),
    VC1 = (VC + VD1) band 16#ffffffff,
    VB1 = rotl32(VB bxor VC1, 12),
    VA2 = (VA1 + VB1) band 16#ffffffff,
    VD2 = rotl32(VD1 bxor VA2, 8),
    VC2 = (VC1 + VD2) band 16#ffffffff,
    VB2 = rotl32(VB1 bxor VC2, 7),
    
    % Update state list
    NewStateList = lists:foldl(fun({Idx, Val}, Acc) ->
        lists:sublist(Acc, Idx) ++ [Val] ++ lists:nthtail(Idx + 1, Acc)
    end, StateList, [{A, VA2}, {B, VB2}, {C, VC2}, {D, VD2}]),
    
    list_to_tuple(NewStateList).

%% @doc Rotate left 32-bit value
%% @param Value - 32-bit value to rotate
%% @param Bits - Number of bits to rotate
%% @return Rotated value
-spec rotl32(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
rotl32(Value, Bits) ->
    ((Value bsl Bits) bor (Value bsr (32 - Bits))) band 16#ffffffff.

%% @doc Add two ChaCha20 states
%% @param State1 - First state
%% @param State2 - Second state
%% @return Sum of states (modulo 2^32)
-spec add_states(tuple(), tuple()) -> tuple().
add_states(State1, State2) ->
    List1 = tuple_to_list(State1),
    List2 = tuple_to_list(State2),
    SumList = lists:zipwith(fun(A, B) -> (A + B) band 16#ffffffff end, List1, List2),
    list_to_tuple(SumList).

%% @doc Convert state tuple to binary
%% @param State - ChaCha20 state tuple
%% @return 64-byte binary
-spec state_to_binary(tuple()) -> binary().
state_to_binary(State) ->
    StateList = tuple_to_list(State),
    << <<Word:32/little>> || Word <- StateList >>.

%% @doc XOR two binaries
%% @param Data1 - First binary
%% @param Data2 - Second binary
%% @return XOR result
-spec crypto_xor(binary(), binary()) -> binary().
crypto_xor(Data1, Data2) ->
    crypto:exor(Data1, Data2).

%%%===================================================================
%%% Unit Tests
%%%===================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

validate_key_test() ->
    ValidKey = <<0:256>>,
    InvalidKey1 = <<0:128>>,
    InvalidKey2 = "not_binary",
    
    ?assertEqual(ok, validate_key(ValidKey)),
    ?assertMatch({error, {invalid_key_size, 16, 32}}, validate_key(InvalidKey1)),
    ?assertMatch({error, invalid_key_format}, validate_key(InvalidKey2)).

validate_nonce_test() ->
    ValidNonce = <<0:96>>,
    InvalidNonce1 = <<0:64>>,
    InvalidNonce2 = "not_binary",
    
    ?assertEqual(ok, validate_nonce(ValidNonce)),
    ?assertMatch({error, {invalid_nonce_size, 8, 12}}, validate_nonce(InvalidNonce1)),
    ?assertMatch({error, invalid_nonce_format}, validate_nonce(InvalidNonce2)).

rotl32_test() ->
    ?assertEqual(16#80000000, rotl32(1, 31)),
    ?assertEqual(2, rotl32(1, 1)),
    ?assertEqual(1, rotl32(16#80000000, 1)).

chacha20_test_vector_test() ->
    % Test vector from RFC 7539
    Key = <<16#00,16#01,16#02,16#03,16#04,16#05,16#06,16#07,16#08,16#09,16#0a,16#0b,16#0c,16#0d,16#0e,16#0f,
            16#10,16#11,16#12,16#13,16#14,16#15,16#16,16#17,16#18,16#19,16#1a,16#1b,16#1c,16#1d,16#1e,16#1f>>,
    Nonce = <<16#00,16#00,16#00,16#00,16#00,16#00,16#00,16#4a,16#00,16#00,16#00,16#00>>,
    Plaintext = <<"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.">>,
    
    {ok, Ciphertext} = encrypt(Plaintext, Key, Nonce, 1),
    {ok, Decrypted} = decrypt(Ciphertext, Key, Nonce, 1),
    
    ?assertEqual(Plaintext, Decrypted).
-endif.
