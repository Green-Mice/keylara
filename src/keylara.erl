%%%===================================================================
%%% File: src/keylara.erl
%%% Description: Main Keylara cryptographic module with entropy management
%%%===================================================================
-module(keylara).
-export([
    % Utility functions
    start/0,
    stop/0,
    get_version/0,
    % Entropy functions
    get_entropy_bytes/2
]).
-include("keylara.hrl").
-include_lib("alara/include/alara.hrl").

%%%===================================================================
%%% Utility Functions
%%%===================================================================

%% @doc Start the Keylara application
%% @return ok | {error, Reason}
-spec start() -> ok | {error, term()}.
start() ->
    % Start required applications
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),
    % Start Alara if available
    case application:ensure_all_started(alara) of
        {ok, _} ->
            io:format("Keylara started successfully with Alara network~n"),
            ok;
        {error, {alara, _}} ->
            io:format("Keylara started in standalone mode (Alara not available)~n"),
            ok;
        {error, Reason} ->
            {error, {failed_to_start_dependencies, Reason}}
    end.

%% @doc Stop the Keylara application
%% @return ok
-spec stop() -> ok.
stop() ->
    application:stop(alara),
    io:format("Keylara stopped~n"),
    ok.

%% @doc Get Keylara version
%% @return Version string
-spec get_version() -> string().
get_version() ->
    "1.0.0-simplified".

%%%===================================================================
%%% Entropy Management Functions
%%%===================================================================

%% @doc Get entropy as bytes from Alara network
%% @param NetPid - Alara network process ID
%% @param BytesNeeded - Number of entropy bytes required
%% @return {ok, EntropyBytes} | {error, Reason}
-spec get_entropy_bytes(pid(), non_neg_integer()) -> {ok, binary()} | {error, term()}.
get_entropy_bytes(NetPid, BytesNeeded) when is_integer(BytesNeeded), BytesNeeded > 0 ->
    try
        case gen_server:call(NetPid, get_network_state) of
            {ok, Network} ->
                Pool = Network#distributed_entropy_network.global_entropy_pool,
                BitsNeeded = BytesNeeded * 8,
                if
                    length(Pool) >= BitsNeeded ->
                        EntropyBits = lists:sublist(Pool, BitsNeeded),
                        {ok, bits_to_bytes(EntropyBits, BytesNeeded)};
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
get_entropy_bytes(_NetPid, BytesNeeded) ->
    {error, {invalid_bytes_requested, BytesNeeded}}.

%%%===================================================================
%%% Internal Helper Functions
%%%===================================================================

%% @doc Convert entropy bits to bytes
%% @param Bits - List of boolean entropy bits
%% @param NumBytes - Number of bytes needed
%% @return Binary entropy bytes
-spec bits_to_bytes([boolean()], non_neg_integer()) -> binary().
bits_to_bytes(Bits, NumBytes) ->
    list_to_binary([bits_to_byte(lists:sublist(Bits, (I-1)*8 + 1, 8)) || I <- lists:seq(1, NumBytes)]).

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

