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

%%%===================================================================
%%% Application Management
%%%===================================================================

%% @doc Start Keylara and its dependencies.
%%
%% Starts the crypto, public_key, and alara OTP applications.
%% The ALARA entropy pool starts automatically as part of the alara
%% application (pool size configured via {alara, [{pool_size, N}]}).
-spec start() -> ok | {error, term()}.
start() ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),
    case application:ensure_all_started(alara) of
        {ok, _} -> ok;
        {error, Reason} -> {error, {failed_to_start_alara, Reason}}
    end.

%% @doc Stop Keylara.
%%
%% Note: the ALARA entropy pool is managed by the OTP application framework.
%% Its lifecycle is tied to the application that declared alara in its
%% {applications, [...]} list. Stopping it here would affect all callers
%% on the node.
-spec stop() -> ok.
stop() ->
    ok.

%% @doc Return the current Keylara version string.
-spec get_version() -> string().
get_version() ->
    "1.0.3".

%% @doc Return the PID of the running ALARA entropy pool supervisor.
-spec get_network_pid() -> {ok, pid()} | {error, term()}.
get_network_pid() ->
    case whereis(alara_node_sup) of
        undefined        -> {error, network_not_initialized};
        Pid when is_pid(Pid) -> {ok, Pid}
    end.

%%%===================================================================
%%% Entropy Management
%%%===================================================================

%% @doc Get NBytes cryptographically secure random bytes from ALARA.
%%
%% The ALARA pool collects entropy from all worker nodes in parallel
%% and mixes the result with SHA3-256 before returning it.
%% This function is the single point of entropy consumption for all
%% KeyLARA cryptographic operations (AES, ChaCha20, RSA, ML-KEM, ...).
%%
%% Returns {error, {failed_to_get_entropy, no_nodes}} if the alara
%% application has not been started yet.
-spec get_entropy_bytes(pos_integer()) -> {ok, binary()} | {error, term()}.
get_entropy_bytes(NBytes) when is_integer(NBytes), NBytes > 0 ->
    case alara:generate_random_bytes(NBytes) of
        Bytes when is_binary(Bytes), byte_size(Bytes) =:= NBytes ->
            {ok, Bytes};
        {error, Reason} ->
            {error, {failed_to_get_entropy, Reason}};
        Other ->
            {error, {failed_to_get_entropy, {unexpected_result, Other}}}
    end;
get_entropy_bytes(NBytes) ->
    {error, {invalid_byte_count, NBytes}}.
