%%%===================================================================
%%% File: src/keylara.erl
%%% Description: Main Keylara cryptographic module (simplified)
%%%===================================================================
-module(keylara).

-export([
    % Utility functions
    start/0,
    stop/0,
    get_version/0
]).

-include("keylara.hrl").
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
