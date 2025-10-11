%%%===================================================================
%%% Keylara - Lightweight Cryptographic Entropy Module
%%% Centralized entropy management with ALARA integration
%%%===================================================================
-module(keylara).

-export([
    start/0,
    stop/0,
    get_version/0,
    get_entropy_bytes/1,
    seed_random/0,
    get_network_pid/0
]).

-include_lib("alara/include/alara.hrl").

-define(NETWORK_KEY, keylara_network_pid).

%%%===================================================================
%%% Application Management
%%%===================================================================

%% @doc Start Keylara and its dependencies
-spec start() -> ok | {error, term()}.
start() ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),
    case application:ensure_all_started(alara) of
        {ok, _} ->
            %% Create the ALARA network and store its PID
            case alara:create_network() of
                {ok, NetPid} ->
                    persistent_term:put(?NETWORK_KEY, NetPid),
                    io:format("Keylara started with ALARA entropy system (Network PID: ~p)~n", [NetPid]),
                    ok;
                {error, Reason} ->
                    {error, {failed_to_create_network, Reason}}
            end;
        {error, {alara, _}} ->
            io:format("Keylara started without ALARA (standalone mode)~n"),
            ok;
        {error, Reason} ->
            {error, {failed_to_start, Reason}}
    end.

%% @doc Stop Keylara and its dependencies
-spec stop() -> ok.
stop() ->
    %% Clean up network PID if it exists
    case persistent_term:get(?NETWORK_KEY, undefined) of
        undefined -> ok;
        _NetPid -> persistent_term:erase(?NETWORK_KEY)
    end,
    application:stop(alara),
    io:format("Keylara stopped~n"),
    ok.

%% @doc Return Keylara version
-spec get_version() -> string().
get_version() ->
    "1.0.2-centralized".

%% @doc Get the network PID (internal use)
-spec get_network_pid() -> {ok, pid()} | {error, term()}.
get_network_pid() ->
    case persistent_term:get(?NETWORK_KEY, undefined) of
        undefined -> {error, network_not_initialized};
        NetPid when is_pid(NetPid) -> {ok, NetPid};
        _ -> {error, invalid_network_pid}
    end.

%%%===================================================================
%%% Entropy Management
%%%===================================================================

%% @doc Get random entropy bytes from the ALARA network
%% @param NBytes - Number of bytes required
%% @return {ok, Binary} | {error, Reason}
-spec get_entropy_bytes(non_neg_integer()) -> {ok, binary()} | {error, term()}.
get_entropy_bytes(NBytes) when is_integer(NBytes), NBytes > 0 ->
    case get_network_pid() of
        {ok, _NetPid} ->
            BitsNeeded = NBytes * 8,
            try
                %% Use ALARA to generate distributed random bits
                Bits = alara:generate_random_bools(BitsNeeded),
                {ok, bits_to_bytes(Bits, NBytes)}
            catch
                _:Reason ->
                    {error, {failed_to_get_entropy, Reason}}
            end;
        {error, Reason} ->
            {error, Reason}
    end;
get_entropy_bytes(NBytes) ->
    {error, {invalid_byte_count, NBytes}}.

%% @doc Seed Erlang's random number generator with Alara entropy
%% @return ok | {error, Reason}
-spec seed_random() -> ok | {error, term()}.
seed_random() ->
    case get_entropy_bytes(12) of % 3 * 32 bits = 96 bits = 12 bytes
        {ok, EntropyBytes} ->
            <<Seed1:32, Seed2:32, Seed3:32, _/binary>> = EntropyBytes,
            rand:seed(exrop, {Seed1, Seed2, Seed3}),
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

%%%===================================================================
%%% Internal Helpers
%%%===================================================================

-spec bits_to_bytes([boolean()], non_neg_integer()) -> binary().
bits_to_bytes(Bits, NBytes) ->
    list_to_binary(
        [bits_to_byte(lists:sublist(Bits, (I-1)*8 + 1, 8))
         || I <- lists:seq(1, NBytes)]
    ).

-spec bits_to_byte([boolean()]) -> byte().
bits_to_byte(Bits) ->
    bits_to_byte(Bits, 0, 0).

bits_to_byte([], _, Acc) ->
    Acc;
bits_to_byte([Bit | Rest], Shift, Acc) ->
    Value = case Bit of
        true -> 1;
        false -> 0;
        1 -> 1;
        0 -> 0
    end,
    bits_to_byte(Rest, Shift + 1, Acc bor (Value bsl Shift)).

