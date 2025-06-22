%%%===================================================================
%%% File: src/keylara_entropy.erl
%%% Description: Entropy management using Alara distributed network
%%%===================================================================

-module(keylara_entropy).

-export([
    get_entropy_bits/2,
    get_entropy_bytes/2,
    seed_random/1
]).

-include("keylara.hrl").
-include_lib("alara/include/alara.hrl").

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Get entropy bits from Alara network
%% @param NetPid - Alara network process ID
%% @param BitsNeeded - Number of entropy bits required
%% @return {ok, EntropyBits} | {error, Reason}
-spec get_entropy_bits(pid(), non_neg_integer()) -> {ok, [boolean()]} | entropy_error().
get_entropy_bits(NetPid, BitsNeeded) when is_pid(NetPid), is_integer(BitsNeeded), BitsNeeded > 0 ->
    try
        % Get current network state from Alara
        case gen_server:call(NetPid, get_network_state) of
            {ok, Network} ->
                Pool = Network#distributed_entropy_network.global_entropy_pool,
                % Check if we have enough entropy
                if
                    length(Pool) >= BitsNeeded ->
                        EntropyBits = lists:sublist(Pool, BitsNeeded),
                        {ok, EntropyBits};
                    true ->
                        {error, {insufficient_entropy, length(Pool), BitsNeeded}}
                end;
            {error, NetworkReason} ->
                {error, {alara_network_error, network_state_failed, NetworkReason}}
        end
    catch
        Error:CatchReason:Stack ->
            {error, {alara_network_error, Error, {CatchReason, Stack}}}
    end;
get_entropy_bits(_NetPid, BitsNeeded) when BitsNeeded =< 0 ->
    {error, {invalid_bits_requested, BitsNeeded}};
get_entropy_bits(NetPid, _BitsNeeded) ->
    {error, {invalid_network_pid, NetPid}}.

%% @doc Get entropy as bytes from Alara network
%% @param NetPid - Alara network process ID
%% @param BytesNeeded - Number of entropy bytes required
%% @return {ok, EntropyBytes} | {error, Reason}
-spec get_entropy_bytes(pid(), non_neg_integer()) -> {ok, binary()} | entropy_error().
get_entropy_bytes(NetPid, BytesNeeded) when is_integer(BytesNeeded), BytesNeeded > 0 ->
    BitsNeeded = BytesNeeded * 8,
    case get_entropy_bits(NetPid, BitsNeeded) of
        {ok, EntropyBits} ->
            EntropyBytes = bits_to_bytes(EntropyBits, BytesNeeded),
            {ok, EntropyBytes};
        {error, ErrorReason} ->
            {error, ErrorReason}
    end;
get_entropy_bytes(_NetPid, BytesNeeded) ->
    {error, {invalid_bytes_requested, BytesNeeded}}.

%% @doc Seed Erlang's random number generator with Alara entropy
%% @param NetPid - Alara network process ID
%% @return ok | {error, Reason}
-spec seed_random(pid()) -> ok | entropy_error().
seed_random(NetPid) ->
    case get_entropy_bits(NetPid, 96) of % 3 * 32 bits for the seed
        {ok, EntropyBits} ->
            % Convert entropy bits to integers for seeding
            Seed1 = bits_to_integer(lists:sublist(EntropyBits, 32)),
            Seed2 = bits_to_integer(lists:sublist(EntropyBits, 33, 32)),
            Seed3 = bits_to_integer(lists:sublist(EntropyBits, 65, 32)),
            % Seed the random number generator
            rand:seed(exrop, {Seed1, Seed2, Seed3}),
            ok;
        {error, SeedReason} ->
            {error, SeedReason}
    end.

%%%===================================================================
%%% Internal Helper Functions
%%%===================================================================

%% @doc Convert entropy bits to bytes
%% @param Bits - List of boolean entropy bits
%% @param NumBytes - Number of bytes needed
%% @return Binary entropy bytes
-spec bits_to_bytes([boolean()], non_neg_integer()) -> binary().
bits_to_bytes(Bits, NumBytes) ->
    % Group bits into bytes (groups of 8 bits)
    ByteBits = group_bits_into_bytes(Bits, NumBytes),
    % Convert each group of 8 bits to a byte
    KeyBytesList = [bits_to_byte(BitGroup) || BitGroup <- ByteBits],
    list_to_binary(KeyBytesList).

%% @doc Group entropy bits into bytes (groups of 8 bits)
%% @param Bits - List of boolean bits
%% @param NumBytes - Number of bytes needed
%% @return List of bit groups (each group has 8 bits)
-spec group_bits_into_bytes([boolean()], non_neg_integer()) -> [[boolean()]].
group_bits_into_bytes(Bits, NumBytes) ->
    group_bits_into_bytes(Bits, NumBytes, []).

-spec group_bits_into_bytes([boolean()], non_neg_integer(), [[boolean()]]) -> [[boolean()]].
group_bits_into_bytes(_Bits, 0, Acc) ->
    lists:reverse(Acc);
group_bits_into_bytes(Bits, NumBytes, Acc) ->
    {ByteBits, Rest} = lists:split(8, Bits),
    group_bits_into_bytes(Rest, NumBytes - 1, [ByteBits | Acc]).

%% @doc Convert 8 bits to a byte value
%% @param Bits - List of 8 boolean values
%% @return Integer byte value (0-255)
-spec bits_to_byte([boolean()]) -> byte().
bits_to_byte(Bits) ->
    bits_to_byte(Bits, 0, 0).

-spec bits_to_byte([boolean()], non_neg_integer(), non_neg_integer()) -> byte().
bits_to_byte([], _Power, Acc) ->
    Acc;
bits_to_byte([Bit | Rest], Power, Acc) ->
    Value = case Bit of
        true -> 1;
        false -> 0;
        1 -> 1;
        0 -> 0
    end,
    bits_to_byte(Rest, Power + 1, Acc bor (Value bsl Power)).

%% @doc Convert list of boolean bits to integer
%% @param Bits - List of boolean values representing bits
%% @return Integer representation of the bits
-spec bits_to_integer([boolean()]) -> non_neg_integer().
bits_to_integer(Bits) ->
    bits_to_integer(Bits, 0, 0).

-spec bits_to_integer([boolean()], non_neg_integer(), non_neg_integer()) -> non_neg_integer().
bits_to_integer([], _Power, Acc) ->
    round(Acc);
bits_to_integer([Bit | Rest], Power, Acc) ->
    Value = case Bit of
        true -> 1;
        false -> 0;
        1 -> 1;
        0 -> 0
    end,
    bits_to_integer(Rest, Power + 1, Acc + (Value * math:pow(2, Power))).
