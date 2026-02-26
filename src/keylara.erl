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
    get_network_pid/0
]).

-define(NETWORK_KEY, keylara_network_pid).

%%%===================================================================
%%% Application Management
%%%===================================================================

%% @doc Start Keylara and its dependencies.
%%
%% Starts the `crypto`, `public_key`, and `alara` OTP applications, then
%% creates an ALARA entropy pool and stores its PID in a persistent term
%% for fast, lock-free access by `get_entropy_bytes/1`.
-spec start() -> ok | {error, term()}.
start() ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),
    case application:ensure_all_started(alara) of
        {ok, _} ->
            case alara:create_network() of
                {ok, NetPid} ->
                    persistent_term:put(?NETWORK_KEY, NetPid),
                    io:format("Keylara started with ALARA entropy pool (PID: ~p)~n", [NetPid]),
                    ok;
                {error, Reason} ->
                    {error, {failed_to_create_network, Reason}}
            end;
        {error, Reason} ->
            {error, {failed_to_start_alara, Reason}}
    end.

%% @doc Stop Keylara and release the entropy pool PID.
-spec stop() -> ok.
stop() ->
    case persistent_term:get(?NETWORK_KEY, undefined) of
        undefined -> ok;
        _         -> persistent_term:erase(?NETWORK_KEY)
    end,
    application:stop(alara),
    io:format("Keylara stopped~n"),
    ok.

%% @doc Return the current Keylara version string.
-spec get_version() -> string().
get_version() ->
    "1.0.3".

%% @doc Return the PID of the running ALARA entropy network.
-spec get_network_pid() -> {ok, pid()} | {error, term()}.
get_network_pid() ->
    case persistent_term:get(?NETWORK_KEY, undefined) of
        undefined        -> {error, network_not_initialized};
        Pid when is_pid(Pid) -> {ok, Pid};
        _                -> {error, invalid_network_pid}
    end.

%%%===================================================================
%%% Entropy Management
%%%===================================================================

%% @doc Get `NBytes` cryptographically secure random bytes from ALARA.
%%
%% The ALARA network collects entropy from all its worker nodes in
%% parallel and mixes the result with SHA3-256 before returning it.
%% This function is the single point of entropy consumption for all
%% KeyLARA cryptographic operations (AES, ChaCha20, RSA, ML-KEM, …).
%%
%% Returns `{error, network_not_initialized}` if `keylara:start/0` has
%% not been called yet.
-spec get_entropy_bytes(pos_integer()) -> {ok, binary()} | {error, term()}.
get_entropy_bytes(NBytes) when is_integer(NBytes), NBytes > 0 ->
    case get_network_pid() of
        {ok, _Pid} ->
            %% alara:generate_random_bytes/1 calls crypto:strong_rand_bytes/1
            %% on every worker and mixes contributions with SHA3-256.
            case alara:generate_random_bytes(NBytes) of
                Bytes when is_binary(Bytes), byte_size(Bytes) =:= NBytes ->
                    {ok, Bytes};
                {error, Reason} ->
                    {error, {failed_to_get_entropy, Reason}};
                Other ->
                    {error, {failed_to_get_entropy, {unexpected_result, Other}}}
            end;
        {error, Reason} ->
            {error, {failed_to_get_entropy, Reason}}
    end;
get_entropy_bytes(NBytes) ->
    {error, {invalid_byte_count, NBytes}}.
