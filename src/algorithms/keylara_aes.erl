%%%===================================================================
%%% File: src/algorithms/keylara_aes.erl
%%% Description: AES encryption/decryption functions
%%%===================================================================

-module(keylara_aes).

-export([
    generate_key/1,
    generate_key/2,
    encrypt/2,
    encrypt/3,
    decrypt/2,
    decrypt/3,
    generate_iv/0,
    get_key_type/1,
    validate_key/1,
    validate_iv/1
]).

-include("keylara.hrl").

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Generate AES key using Alara distributed entropy network
%% @param NetPid - Process ID of the Alara network
%% @return {ok, AESKey} | {error, Reason} - Generates AES-256 key by default
-spec generate_key(pid()) -> {ok, aes_key()} | keylara_error().
generate_key(NetPid) ->
    generate_key(NetPid, ?AES_256).

%% @doc Generate AES key of specific size using Alara distributed entropy network
%% @param NetPid - Process ID of the Alara network
%% @param KeySize - AES key size in bits (128, 192, or 256)
%% @return {ok, AESKey} | {error, Reason}
-spec generate_key(pid(), aes_key_size()) -> {ok, aes_key()} | keylara_error().
generate_key(NetPid, KeySize) when KeySize =:= ?AES_128; KeySize =:= ?AES_192; KeySize =:= ?AES_256 ->
    try
        case keylara_entropy:generate_aes_key(NetPid, KeySize) of
            {ok, AESKey} ->
                {ok, AESKey};
            {error, EntropyReason} ->
                {error, {entropy_generation_failed, EntropyReason}}
        end
    catch
        Error:CatchReason:Stack ->
            {error, {aes_key_generation_failed, Error, CatchReason, Stack}}
    end;
generate_key(_NetPid, KeySize) ->
    {error, {invalid_key_size, KeySize, "Must be 128, 192, or 256 bits"}}.

%% @doc Generate random IV for AES
%% @return 16-byte IV
-spec generate_iv() -> aes_iv().
generate_iv() ->
    keylara_entropy:generate_secure_bytes(?AES_IV_SIZE).

%% @doc Encrypt data using AES with a randomly generated IV
%% @param Data - Binary data to encrypt
%% @param AESKey - AES encryption key
%% @return {ok, {IV, EncryptedData}} | {error, Reason}
-spec encrypt(binary(), aes_key()) -> {ok, aes_encrypted()} | keylara_error().
encrypt(Data, AESKey) when is_binary(Data), is_binary(AESKey) ->
    try
        % Validate key
        case validate_key(AESKey) of
            ok ->
                % Generate random IV
                IV = generate_iv(),
                % Encrypt with generated IV
                case encrypt(Data, AESKey, IV) of
                    {ok, EncryptedData} ->
                        {ok, {IV, EncryptedData}};
                    {error, Reason} ->
                        {error, Reason}
                end;
            {error, KeyError} ->
                {error, KeyError}
        end
    catch
        Error:CatchReason:Stack ->
            {error, {aes_encryption_failed, Error, CatchReason, Stack}}
    end;
encrypt(Data, AESKey) when is_list(Data) ->
    encrypt(list_to_binary(Data), AESKey);
encrypt(Data, AESKey) ->
    {error, {invalid_input, {data, Data}, {key, AESKey}}}.

%% @doc Encrypt data using AES with specified IV
%% @param Data - Binary data to encrypt
%% @param AESKey - AES encryption key
%% @param IV - Initialization Vector (must be 16 bytes for AES)
%% @return {ok, EncryptedData} | {error, Reason}
-spec encrypt(binary(), aes_key(), aes_iv()) -> {ok, binary()} | keylara_error().
encrypt(Data, AESKey, IV) when is_binary(Data), is_binary(AESKey), is_binary(IV) ->
    try
        % Validate inputs
        case validate_key(AESKey) of
            ok ->
                case validate_iv(IV) of
                    ok ->
                        % Determine AES mode based on key size
                        case get_key_type(AESKey) of
                            {ok, AESType} ->
                                % Pad data to block size (PKCS#7 padding)

                                PaddedData = pkcs7_pad(Data, ?AES_BLOCK_SIZE),
                                % Encrypt using crypto module
                                EncryptedData = crypto:crypto_one_time(AESType, AESKey, IV, PaddedData, true),
                                {ok, EncryptedData};
                            {error, KeyError} ->
                                {error, KeyError}
                        end;
                    {error, IVError} ->
                        {error, IVError}
                end;
            {error, KeyError} ->
                {error, KeyError}
        end
    catch
        Error:CatchReason:Stack ->
            {error, {aes_encryption_failed, Error, CatchReason, Stack}}
    end;
encrypt(Data, AESKey, IV) when is_list(Data) ->
    encrypt(list_to_binary(Data), AESKey, IV);
encrypt(Data, AESKey, IV) ->
    {error, {invalid_input, {data, Data}, {key, AESKey}, {iv, IV}}}.

%% @doc Decrypt data using AES with IV
%% @param IVAndEncryptedData - Tuple {IV, EncryptedData} or just EncryptedData if IV separate
%% @param AESKey - AES decryption key
%% @return {ok, DecryptedData} | {error, Reason}
-spec decrypt(aes_encrypted() | binary(), aes_key()) -> {ok, binary()} | keylara_error().
decrypt({IV, EncryptedData}, AESKey) when is_binary(IV), is_binary(EncryptedData), is_binary(AESKey) ->
    decrypt(EncryptedData, AESKey, IV);
decrypt(EncryptedData, AESKey) when is_binary(EncryptedData), is_binary(AESKey) ->
    {error, {missing_iv, "IV required for AES decryption"}};
decrypt(Input, AESKey) ->
    {error, {invalid_input, {encrypted_data, Input}, {key, AESKey}}}.

%% @doc Decrypt data using AES with specified IV
%% @param EncryptedData - Binary encrypted data
%% @param AESKey - AES decryption key
%% @param IV - Initialization Vector (must be 16 bytes for AES)
%% @return {ok, DecryptedData} | {error, Reason}
-spec decrypt(binary(), aes_key(), aes_iv()) -> {ok, binary()} | keylara_error().
decrypt(EncryptedData, AESKey, IV) when is_binary(EncryptedData), is_binary(AESKey), is_binary(IV) ->
    try
        % Validate inputs
        case validate_key(AESKey) of
            ok ->
                case validate_iv(IV) of
                    ok ->
                        % Determine AES mode based on key size
                        case get_key_type(AESKey) of
                            {ok, AESType} ->
                                % Decrypt using crypto module
                                PaddedData = crypto:crypto_one_time(AESType, AESKey, IV, EncryptedData, false),
                                % Remove PKCS#7 padding
                                case pkcs7_unpad(PaddedData) of
                                    {ok, DecryptedData} ->
                                        {ok, DecryptedData};
                                    {error, Reason} ->
                                        {error, Reason}
                                end;
                            {error, KeyError} ->
                                {error, KeyError}
                        end;
                    {error, IVError} ->
                        {error, IVError}
                end;
            {error, KeyError} ->
                {error, KeyError}
        end
    catch
        Error:CatchReason:Stack ->
            {error, {aes_decryption_failed, Error, CatchReason, Stack}}
    end;
decrypt(EncryptedData, AESKey, IV) ->
    {error, {invalid_input, {encrypted_data, EncryptedData}, {key, AESKey}, {iv, IV}}}.

%% @doc Get AES cipher type based on key size
%% @param AESKey - AES key
%% @return {ok, AESType} | {error, Reason}
-spec get_key_type(aes_key()) -> {ok, atom()} | keylara_error().
get_key_type(AESKey) when is_binary(AESKey) ->
    KeySize = byte_size(AESKey) * 8,
    case KeySize of
        128 -> {ok, aes_128_cbc};
        192 -> {ok, aes_192_cbc};
        256 -> {ok, aes_256_cbc};
        _ -> {error, {invalid_aes_key_size, KeySize}}
    end;
get_key_type(AESKey) ->
    {error, {invalid_key_type, AESKey}}.

%% @doc Validate AES key
%% @param AESKey - AES key to validate
%% @return ok | {error, Reason}
-spec validate_key(aes_key()) -> ok | keylara_error().
validate_key(AESKey) when is_binary(AESKey) ->
    KeySize = byte_size(AESKey) * 8,
    case KeySize of
        128 -> ok;
        192 -> ok;
        256 -> ok;
        _ -> {error, {invalid_aes_key_size, KeySize}}
    end;
validate_key(AESKey) ->
    {error, {invalid_key_type, AESKey}}.

%% @doc Validate AES IV
%% @param IV - IV to validate
%% @return ok | {error, Reason}
-spec validate_iv(aes_iv()) -> ok | keylara_error().
validate_iv(IV) when is_binary(IV) ->
    case byte_size(IV) of
        ?AES_IV_SIZE -> ok;
        Size -> {error, {invalid_iv_size, Size, "IV must be 16 bytes for AES"}}
    end;
validate_iv(IV) ->
    {error, {invalid_iv_type, IV}}.

%%%===================================================================
%%% PKCS#7 Padding Functions
%%%===================================================================

%% @doc Add PKCS#7 padding to data
%% @param Data - Binary data to pad
%% @param BlockSize - Block size for padding
%% @return Padded binary data
-spec pkcs7_pad(binary(), pos_integer()) -> binary().
pkcs7_pad(Data, BlockSize) when is_binary(Data), is_integer(BlockSize), BlockSize > 0 ->
    DataSize = byte_size(Data),
    PadSize = BlockSize - (DataSize rem BlockSize),
    PadByte = <<PadSize>>,
    PadData = binary:copy(PadByte, PadSize),
    <<Data/binary, PadData/binary>>.

%% @doc Remove PKCS#7 padding from data
%% @param PaddedData - Binary data with PKCS#7 padding
%% @return {ok, UnpaddedData} | {error, Reason}
-spec pkcs7_unpad(binary()) -> {ok, binary()} | keylara_error().
pkcs7_unpad(PaddedData) when is_binary(PaddedData) ->
    try
        DataSize = byte_size(PaddedData),
        if
            DataSize =:= 0 ->
                {error, empty_data};
            true ->
                % Get the last byte which indicates padding size
                <<_:((DataSize-1)*8), PadSize:8>> = PaddedData,
                % Validate padding size
                if
                    PadSize =< 0; PadSize > DataSize ->
                        {error, {invalid_padding_size, PadSize}};
                    true ->
                        % Extract the actual data (without padding)
                        ActualDataSize = DataSize - PadSize,
                        <<ActualData:ActualDataSize/binary, _Padding/binary>> = PaddedData,
                        % Verify that all padding bytes are correct
                        PaddingBytes = binary:part(PaddedData, ActualDataSize, PadSize),
                        ExpectedPadding = binary:copy(<<PadSize>>, PadSize),
                        case PaddingBytes of
                            ExpectedPadding ->
                                {ok, ActualData};
                            _ ->
                                {error, invalid_padding_bytes}
                        end
                end
        end
    catch
        Error:Reason:Stack ->
            {error, {padding_removal_failed, Error, Reason, Stack}}
    end;
pkcs7_unpad(PaddedData) ->
    {error, {invalid_data_type, PaddedData}}.
